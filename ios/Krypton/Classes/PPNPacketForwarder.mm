/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketForwarder.h"

#include <algorithm>
#include <utility>

#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/Classes/NSObject+PPNKVO.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacket.h"

#include "third_party/absl/synchronization/blocking_counter.h"

const int kUplinkPacketBufferSize = 128;
const int kDownlinkPacketBufferSize = 64;
const NSTimeInterval kSessionReadyTimeout = 60.0;
const NSTimeInterval kSessionWriteTimeout = 5.0;
const NSTimeInterval kEncryptionTimeout = 60.0;

@interface PPNPacketForwarder ()

// Called when the underlying session's state changes.
- (void)observeStateChangedTo:(NWUDPSessionState)state;

// Called when the underlying session's hasBetterPath becomes true.
- (void)observeHasBetterPath;

// Blocks until the session is ready, times out, or becomes failed/cancelled.
- (absl::Status)waitForSessionReadyWithTimeout:(NSTimeInterval)sessionReadyTimeout;

// Recursively takes packets from the tunnel, encrypts them, and sends them over the network.
- (void)processUplinkWithWriteTimeout:(NSTimeInterval)writeTimeout;

// Handles one callback from the packet tunnel flow callback.
- (void)processUplinkPackets:(NSArray<NEPacket *> *)packets
            withWriteTimeout:(NSTimeInterval)writeTimeout;

// Starts taking packets from the network, decrypting them, and sending them to the tunnel.
- (void)processDownlink;

// Handles one callback from the session readHandler.
- (void)processDownlinkPackets:(NSArray<NSData *> *)datagrams error:(NSError *)error;

// Marks the forwarder as failed and sends a failed notification.
- (void)failWithStatus:(const absl::Status &)status permanently:(BOOL)permanent;
- (void)failWithError:(NSError *)error permanently:(BOOL)permanent;

@end

@implementation PPNPacketForwarder {
  // Immutable state set when creating the forwarder.
  std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecEncryptor> _encryptor;
  std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecDecryptor> _decryptor;
  NEPacketTunnelFlow *_packetTunnelFlow;
  NWUDPSession *_session;

  absl::Mutex _mutex;
  privacy::krypton::PacketForwarderNotificationInterface *_notification ABSL_GUARDED_BY(_mutex);
  privacy::krypton::utils::LooperThread *_notificationLooper ABSL_GUARDED_BY(_mutex);

  // Buffers used to avoid allocating memory when encrypting/decrypting packets.
  privacy::krypton::datapath::ipsec::IpSecPacket _decryptionBuffer[kDownlinkPacketBufferSize];
  privacy::krypton::datapath::ipsec::IpSecPacket _encryptionBuffer[kUplinkPacketBufferSize];
  sa_family_t _decryptedFamilyBuffer[kDownlinkPacketBufferSize];
  BOOL _decryptionSuccess[kDownlinkPacketBufferSize];
  NSMutableArray<NSData *> *_encryptedDatagramBuffer;
  NSMutableArray<NEPacket *> *_decryptedPacketBuffer;

  // Queues to use for parallel encryption/decryption.
  dispatch_queue_t _encryptionQueue;
  dispatch_queue_t _decryptionQueue;

  // Mutable state used to manage the packet forwarder lifecycle.
  BOOL _connected ABSL_GUARDED_BY(_mutex);
  BOOL _stopped ABSL_GUARDED_BY(_mutex);

  // A copy of the state of _session, but guarded by _stateCondition.
  NWUDPSessionState _state;
  // An NSCondition that guards and notifies when _state changes.
  NSCondition *_stateCondition;

  // Metrics.
  std::atomic_int64_t _uplinkPacketsRead;
  std::atomic_int64_t _uplinkPacketsDropped;
  std::atomic_int64_t _downlinkPacketsRead;
  std::atomic_int64_t _downlinkPacketsDropped;
  std::atomic_int64_t _decryptionErrors;
  std::atomic_int64_t _tunnelWriteErrors;
}

// Creates and starts the packet forwarder.
- (instancetype)
        initWithConfig:(const privacy::krypton::KryptonConfig &)config
             encryptor:(std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecEncryptor>)encryptor
             decryptor:(std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecDecryptor>)decryptor
      packetTunnelFlow:(NEPacketTunnelFlow *)packetTunnelFlow
               session:(NWUDPSession *)session
          notification:(privacy::krypton::PacketForwarderNotificationInterface *)notification
    notificationLooper:(privacy::krypton::utils::LooperThread *)notificationLooper {
  self = [super init];
  if (self != nil) {
    _encryptor = std::move(encryptor);
    _decryptor = std::move(decryptor);
    _packetTunnelFlow = packetTunnelFlow;
    _session = session;
    _notification = notification;
    _notificationLooper = notificationLooper;

    _encryptedDatagramBuffer = [NSMutableArray arrayWithCapacity:kUplinkPacketBufferSize];
    _decryptedPacketBuffer = [NSMutableArray arrayWithCapacity:kDownlinkPacketBufferSize];

    if (config.ios_uplink_parallelism_enabled()) {
      _encryptionQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
    } else {
      _encryptionQueue =
          dispatch_queue_create("com.google.ppn.ipsec-encrypt", DISPATCH_QUEUE_SERIAL);
    }
    _decryptionQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);

    _connected = NO;
    _stopped = NO;

    _uplinkPacketsRead = 0;
    _uplinkPacketsDropped = 0;
    _downlinkPacketsRead = 0;
    _downlinkPacketsDropped = 0;
    _decryptionErrors = 0;
    _tunnelWriteErrors = 0;

    // Set up KVO so that we know if state changes.
    _stateCondition = [[NSCondition alloc] init];
    PPNPacketForwarder *weakSelf = self;
    [_session setObserverHandler:^(NSString *keyPath, id object,
                                   NSDictionary<NSKeyValueChangeKey, id> *change,
                                   void *_Nullable context) {
      PPNPacketForwarder *strongSelf = weakSelf;

      // This code is intentionally safe even if strongSelf is nil.
      NWUDPSession *session = object;
      PPNLog(@"[%p] %@ changed to %@ for session %@", strongSelf, keyPath, change[@"new"],
             session.debugDescription);
      if ([keyPath isEqualToString:@"state"]) {
        NWUDPSessionState newState = (NWUDPSessionState)[change[@"new"] intValue];
        [strongSelf observeStateChangedTo:newState];
      }
      if ([keyPath isEqualToString:@"hasBetterPath"]) {
        if ([change[@"new"] boolValue]) {
          [strongSelf observeHasBetterPath];
        }
      }
    }];

    [_session addObserverForKeyPath:@"hasBetterPath"
                            options:NSKeyValueObservingOptionNew
                            context:nullptr];
    [_session addObserverForKeyPath:@"state" options:NSKeyValueObservingOptionNew context:nullptr];

    // Now that KVO is set up to catch changes, set the initial _state.
    [_stateCondition lock];
    _state = _session.state;
    [_stateCondition unlock];
  }
  return self;
}

- (void)dealloc {
  [_session removeObserverForKeyPath:@"hasBetterPath"];
  [_session removeObserverForKeyPath:@"state"];
}

- (void)observeStateChangedTo:(NWUDPSessionState)state {
  [_stateCondition lock];
  _state = state;
  [_stateCondition signal];
  [_stateCondition unlock];
}

- (void)observeHasBetterPath {
  absl::MutexLock l(&_mutex);
  if (!_stopped) {
    _stopped = YES;
    LOG(INFO) << "Notifying datapath that hasBetterPath = YES";
    auto notification = _notification;
    NWUDPSession *session = [[NWUDPSession alloc] initWithUpgradeForSession:_session];
    _notificationLooper->Post(
        [notification, session] { notification->PacketForwarderHasBetterPath(session); });

    [_session cancel];
  }
}

- (absl::Status)waitForSessionReadyWithTimeout:(NSTimeInterval)sessionReadyTimeout {
  absl::Status status = absl::OkStatus();
  NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:sessionReadyTimeout];

  [_stateCondition lock];
  while (_state != NWUDPSessionStateReady) {
    if (_state == NWUDPSessionStateInvalid) {
      PPNLog(@"[%p] NWUDPSession is invalid while waiting for ready.", self);
      status = absl::InternalError("NWUDPSession is invalid");
      break;
    }
    if (_state == NWUDPSessionStateFailed) {
      PPNLog(@"[%p] NWUDPSession is failed while waiting for ready.", self);
      status = absl::InternalError("NWUDPSession is failed");
      break;
    }
    if (![_stateCondition waitUntilDate:timeout]) {
      PPNLog(@"[%p] Timeout in state %d waiting for NWUDPSession to become ready.", self, _state);
      status = absl::DeadlineExceededError(
          absl::StrCat("Timeout in state ", _state, " waiting for pipe to become ready."));
      break;
    }
  }
  [_stateCondition unlock];

  return status;
}

- (void)start {
  [self startWithSessionReadyTimeout:kSessionReadyTimeout sessionWriteTimeout:kSessionWriteTimeout];
}

- (void)startWithSessionReadyTimeout:(NSTimeInterval)sessionReadyTimeout
                 sessionWriteTimeout:(NSTimeInterval)sessionWriteTimeout {
  LOG(INFO) << "Waiting for session to be ready...";
  auto status = [self waitForSessionReadyWithTimeout:sessionReadyTimeout];
  if (!status.ok()) {
    LOG(ERROR) << "Error while waiting for session to become ready: " << status;
    [self failWithStatus:status permanently:NO];
    return;
  }

  LOG(INFO) << "Starting uplink...";
  [self processUplinkWithWriteTimeout:sessionWriteTimeout];
  LOG(INFO) << "Starting downlink...";
  [self processDownlink];
}

- (void)stop {
  LOG(INFO) << "Stopping packet forwarder...";

  // Signal the recursive uplink process to stop.
  absl::MutexLock l(&_mutex);
  _stopped = YES;

  // Cancel the session so that downlink processing stops.
  [_session cancel];
}

- (void)processUplinkWithWriteTimeout:(NSTimeInterval)writeTimeout {
  {
    absl::MutexLock l(&_mutex);
    if (_stopped) {
      return;
    }
  }

  __weak PPNPacketForwarder *weakSelf = self;
  [_packetTunnelFlow readPacketObjectsWithCompletionHandler:^(NSArray<NEPacket *> *packets) {
    [weakSelf processUplinkPackets:packets withWriteTimeout:writeTimeout];
  }];
}

- (void)processUplinkPackets:(NSArray<NEPacket *> *)packets
            withWriteTimeout:(NSTimeInterval)writeTimeout {
  // We don't have control over the number of packets iOS passes to us. Empirically, iOS seems to
  // send us chunks smaller than 64 packets. As long as the chunk is smaller than our buffer size,
  // we won't lose any packets. If the chunk does happen to be larger than our buffer, then we
  // drop the excess packets. Empirically, it's worth losing packets to get the savings from not
  // having to reallocate a new buffer every time. But if we see too many dropped packets, we may
  // want to revisit this decision.
  _uplinkPacketsRead += packets.count;
  if (packets.count > kUplinkPacketBufferSize) {
    _uplinkPacketsDropped += (packets.count - kUplinkPacketBufferSize);
  }
  int uplinkCount = std::min(kUplinkPacketBufferSize, static_cast<int>(packets.count));
  dispatch_group_t group = dispatch_group_create();
  for (int i = 0; i < uplinkCount; i++) {
    dispatch_group_async(group, _encryptionQueue, ^{
      absl::string_view unencryptedData(static_cast<const char *>(packets[i].data.bytes),
                                        packets[i].data.length);
      privacy::krypton::IPProtocol protocol =
          privacy::krypton::IPProtocolFromFamily(packets[i].protocolFamily);
      auto status = _encryptor->Encrypt(unencryptedData, protocol, &(_encryptionBuffer[i]));
      if (!status.ok()) {
        LOG(WARNING) << "Encryption error: " << status;
        [self failWithStatus:status permanently:YES];
      }
    });
  }
  dispatch_time_t encryptionTimeout =
      dispatch_time(DISPATCH_TIME_NOW, kEncryptionTimeout * NSEC_PER_SEC);
  if (dispatch_group_wait(group, encryptionTimeout) != 0) {
    auto status = absl::DeadlineExceededError("Timeout while encrypting packets");
    [self failWithStatus:status permanently:NO];
    return;
  }

  {
    absl::MutexLock l(&_mutex);
    if (_stopped) {
      // Some encryption failed, which is a permanent failure, so don't bother writing packets.
      return;
    }
  }

  // Gather all of the results into one array to write.
  [_encryptedDatagramBuffer removeAllObjects];
  for (int i = 0; i < uplinkCount; i++) {
    privacy::krypton::datapath::ipsec::IpSecPacket *encryptedPacket = &(_encryptionBuffer[i]);
    NSData *encryptedData = [NSData dataWithBytesNoCopy:encryptedPacket->buffer()
                                                 length:encryptedPacket->buffer_size()
                                           freeWhenDone:NO];
    [_encryptedDatagramBuffer addObject:encryptedData];
  }

  __weak PPNPacketForwarder *weakSelf = self;

  // Set up a timeout block to report a failure if the write doesn't succeed quickly enough.
  dispatch_block_t timeoutBlock = dispatch_block_create(static_cast<dispatch_block_flags_t>(0), ^{
    LOG(ERROR) << "UDPSession write timeout";
    [weakSelf failWithStatus:absl::DeadlineExceededError("UDPSession write timeout")
                 permanently:NO];
  });
  dispatch_queue_t timeoutQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
  dispatch_time_t timeoutTime = dispatch_time(DISPATCH_TIME_NOW, writeTimeout * NSEC_PER_SEC);
  dispatch_after(timeoutTime, timeoutQueue, timeoutBlock);

  [_session writeMultipleDatagrams:_encryptedDatagramBuffer
                 completionHandler:^(NSError *_Nullable error) {
                   dispatch_block_cancel(timeoutBlock);
                   if (error != nil) {
                     PPNLog(@"UDPSession write error: %@", error);
                     [weakSelf failWithError:error permanently:NO];
                     return;
                   }
                   [weakSelf processUplinkWithWriteTimeout:writeTimeout];
                 }];
}

- (void)processDownlink {
  __weak PPNPacketForwarder *weakSelf = self;
  [_session
      setReadHandler:^(NSArray<NSData *> *datagrams, NSError *error) {
        [weakSelf processDownlinkPackets:datagrams error:error];
      }
        maxDatagrams:kDownlinkPacketBufferSize];
}

- (void)processDownlinkPackets:(NSArray<NSData *> *)datagrams error:(NSError *)error {
  if (error != nil) {
    PPNLog(@"UDPSession read error: %@", error);
    [self failWithError:error permanently:NO];
    return;
  }

  {
    absl::MutexLock l(&_mutex);
    if (_stopped) {
      return;
    }
    if (!_connected) {
      _connected = YES;
      auto *notification = _notification;
      _notificationLooper->Post([notification]() { notification->PacketForwarderConnected(); });
    }
  }

  // There should never be more packets than the buffer, unless there's a bug in iOS.
  _downlinkPacketsRead += datagrams.count;
  if (datagrams.count > kDownlinkPacketBufferSize) {
    _downlinkPacketsDropped += (datagrams.count - kDownlinkPacketBufferSize);
  }

  int datagramCount = std::min(kDownlinkPacketBufferSize, static_cast<int>(datagrams.count));
  dispatch_group_t group = dispatch_group_create();
  for (int i = 0; i < datagramCount; i++) {
    dispatch_group_async(group, _decryptionQueue, ^{
      absl::string_view encryptedData(static_cast<const char *>(datagrams[i].bytes),
                                      datagrams[i].length);
      privacy::krypton::IPProtocol protocol;
      auto status = _decryptor->Decrypt(encryptedData, &(_decryptionBuffer[i]), &protocol);
      if (!status.ok()) {
        LOG(ERROR) << "Decryption error: " << status;
        _decryptionErrors++;
        _decryptionSuccess[i] = NO;
      } else {
        _decryptedFamilyBuffer[i] = privacy::krypton::FamilyFromIPProtocol(protocol);
        _decryptionSuccess[i] = YES;
      }
    });
  }
  dispatch_time_t decryptionTimeout =
      dispatch_time(DISPATCH_TIME_NOW, kEncryptionTimeout * NSEC_PER_SEC);
  if (dispatch_group_wait(group, decryptionTimeout) != 0) {
    auto status = absl::DeadlineExceededError("Timeout while decrypting packets");
    [self failWithStatus:status permanently:NO];
    return;
  }

  [_decryptedPacketBuffer removeAllObjects];
  for (int i = 0; i < datagramCount; i++) {
    if (!_decryptionSuccess[i]) {
      continue;
    }
    privacy::krypton::datapath::ipsec::IpSecPacket *decryptedPacket = &(_decryptionBuffer[i]);
    sa_family_t family = _decryptedFamilyBuffer[i];
    NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedPacket->data()
                                                 length:decryptedPacket->data_size()
                                           freeWhenDone:NO];
    NEPacket *packet = [[NEPacket alloc] initWithData:decryptedData protocolFamily:family];
    [_decryptedPacketBuffer addObject:packet];
  }

  if (_decryptedPacketBuffer.count == 0) {
    return;
  }

  if (![_packetTunnelFlow writePacketObjects:_decryptedPacketBuffer]) {
    _tunnelWriteErrors++;
    LOG(ERROR) << "Failed to write " << _decryptedPacketBuffer.count << " packets";
  }
}

- (void)collectDebugInfo:(privacy::krypton::DatapathDebugInfo *)debugInfo {
  debugInfo->set_uplink_packets_read(_uplinkPacketsRead);
  debugInfo->set_downlink_packets_read(_downlinkPacketsRead);
  debugInfo->set_uplink_packets_dropped(_uplinkPacketsDropped);
  debugInfo->set_downlink_packets_dropped(_downlinkPacketsDropped);
  debugInfo->set_decryption_errors(_decryptionErrors);
  debugInfo->set_tunnel_write_errors(_tunnelWriteErrors);
}

- (void)failWithStatus:(const absl::Status &)status permanently:(BOOL)permanent {
  absl::MutexLock l(&_mutex);
  if (_stopped) {
    return;
  }
  _stopped = YES;

  LOG(ERROR) << "PacketForwarder failed with status: " << status;

  auto *notification = _notification;
  _notificationLooper->Post([notification, status, permanent]() {
    if (permanent) {
      notification->PacketForwarderPermanentFailure(status);
    } else {
      notification->PacketForwarderFailed(status);
    }
  });

  [_session cancel];
}

- (void)failWithError:(NSError *)error permanently:(BOOL)permanent {
  [self failWithStatus:privacy::krypton::PPNStatusFromNSError(error) permanently:permanent];
}

@end
