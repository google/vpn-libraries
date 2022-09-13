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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNUDPSessionPipe.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/Classes/NSObject+PPNKVO.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacket.h"
#import "privacy/net/krypton/pal/packet.h"
#import "privacy/net/krypton/utils/status.h"
#import "third_party/absl/status/status.h"
#import "third_party/absl/strings/str_cat.h"

static const NSTimeInterval kWaitingTimeout = 60.0;
static const NSTimeInterval kWriteTimeoutInterval = 5.0;
// The maximum number of datagrams to read in one batch.
static const int kMaxDatagrams = 128;

// A wrapper around the calls to the packet pipe to deal with the fact that iOS might call the read
// callback after the object has been destroyed.
@interface PPNUDPSessionPipeWrapper : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithUDPSession:(NWUDPSession *)session
                          protocol:(privacy::krypton::IPProtocol)protocol NS_DESIGNATED_INITIALIZER;

- (void)readPackets:
    (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler;

- (absl::Status)writePackets:(std::vector<::privacy::krypton::Packet>)packets;

- (void)close;

- (void)getDebugInfo:(::privacy::krypton::PacketPipeDebugInfo *)debugInfo;

@end

@implementation PPNUDPSessionPipeWrapper {
  NWUDPSession *_session;
  privacy::krypton::IPProtocol _protocol;
  BOOL _stopped;
  NSLock *_lock;

  // We dispatch all writes to this separate queue, asynchronously. There are multiple reasons why
  // this queue happens here, rather than earlier in the pipeline.
  // 1. We need to block on writes until the completion handler finishes, but we can't block the
  //    thread that got the read callbacks, or else we will deadlock, due to iOS implementation
  //    details. Therefore, we need a separate queue.
  // 2. We want to avoid copies, but it's not documented whether the NSData passed in from the read
  //    method retains its data or not. So, it's safer to queue up the post-encryption packets,
  //    because that is memory that we've allocated ourselves, so we know its lifetime.
  // 3. The size of the queue will grow in proportion to the number of parallel writes. By doing
  //    this after the encryption, we know the upper bound for the number of simultaneous writes has
  //    an upper bound that is the size of the packet pool it borrows from. So we don't need to
  //    worry about the size of the queue here.
  dispatch_queue_t _writeQueue;

  // A copy of the state of _session, but guarded by _stateCondition.
  NWUDPSessionState _state;
  // An NSCondition that guards and notifies when _state changes.
  NSCondition *_stateCondition;

  // Metrics to keep track of how healthy the pipe is.
  std::atomic_int64_t _writesStarted;
  std::atomic_int64_t _writesCompleted;
  std::atomic_int64_t _writeErrors;

  std::atomic<double> _lastWriteStartTime;
}

- (instancetype)initWithUDPSession:(NWUDPSession *)session
                          protocol:(privacy::krypton::IPProtocol)protocol {
  self = [super init];
  if (self != nil) {
    _lock = [[NSLock alloc] init];
    _session = session;
    _protocol = protocol;
    _stopped = NO;
    _stateCondition = [[NSCondition alloc] init];

    _writeQueue = dispatch_queue_create("com.google.ppn.udp-session-writer", DISPATCH_QUEUE_SERIAL);

    _writesStarted = 0;
    _writesCompleted = 0;
    _writeErrors = 0;

    _lastWriteStartTime = [[NSDate distantFuture] timeIntervalSinceReferenceDate];

    // Set up KVO so that we know if state changes.
    PPNUDPSessionPipeWrapper *weakSelf = self;
    [_session setObserverHandler:^(NSString *keyPath, id object,
                                   NSDictionary<NSKeyValueChangeKey, id> *change,
                                   void *_Nullable context) {
      PPNUDPSessionPipeWrapper *strongSelf = weakSelf;

      // This code is intentionally safe even if strongSelf is nil.
      NWUDPSession *session = object;
      PPNLog(@"[%p] %@ changed to %@ for session %@", strongSelf, keyPath, change[@"new"],
             session.debugDescription);
      if ([keyPath isEqualToString:@"state"]) {
        NWUDPSessionState newState = (NWUDPSessionState)[change[@"new"] intValue];
        [strongSelf observeStateChangedTo:newState];
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
  PPNLog(@"[%p] Removing observers for UDP session.", self);
  [_session removeObserverForKeyPath:@"hasBetterPath"];
  [_session removeObserverForKeyPath:@"state"];
}

- (absl::Status)waitForReady {
  absl::Status status = absl::OkStatus();
  NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:kWaitingTimeout];

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

- (absl::Status)waitForCancellation {
  absl::Status status = absl::OkStatus();
  NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kWaitingTimeout];

  [_stateCondition lock];
  while (_state != NWUDPSessionStateCancelled) {
    if (_state == NWUDPSessionStateInvalid) {
      PPNLog(@"[%p] NWUDPSession is invalid while waiting for cancellation.", self);
      status = absl::InternalError("NWUDPSession is invalid");
      break;
    }
    if (_state == NWUDPSessionStateFailed) {
      PPNLog(@"[%p] NWUDPSession is failed while waiting for cancellation.", self);
      status = absl::InternalError("NWUDPSession is failed");
      break;
    }
    if (![_stateCondition waitUntilDate:deadline]) {
      PPNLog(@"[%p] Timeout in state %d waiting for NWUDPSession to become cancelled.", self,
             _state);
      status = absl::DeadlineExceededError(
          absl::StrCat("Timeout in state ", _state, " waiting for pipe to become cancelled."));
      break;
    }
  }
  [_stateCondition unlock];

  return status;
}

- (void)observeStateChangedTo:(NWUDPSessionState)state {
  [_stateCondition lock];
  _state = state;
  [_stateCondition signal];
  [_stateCondition unlock];
}

- (void)readPackets:
    (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler {
  _stopped = NO;
  __weak PPNUDPSessionPipeWrapper *weakSelf = self;
  [_session
      setReadHandler:^(NSArray<NSData *> *datagrams, NSError *error) {
        // If the PPNUDPSessionPipe that owns this wrapper is deleted, then this wrapper can be set
        // to nil. If that happens, then we should stop calling the handler.
        PPNUDPSessionPipeWrapper *strongSelf = weakSelf;
        if (strongSelf == nil) {
          return;
        }

        [strongSelf->_lock lock];
        if (strongSelf->_stopped) {
          if (error != nil) {
            PPNLog(@"[%p] Ignoring UDPSession error callback, because pipe is stopped: %@",
                   strongSelf, error);
          } else {
            PPNLog(@"[%p] Ignoring UDPSession success callback, because pipe is stopped.",
                   strongSelf);
          }
          [strongSelf->_lock unlock];
          return;
        }

        std::vector<::privacy::krypton::Packet> packets;
        packets.reserve(datagrams.count);

        if (error != nil) {
          handler(privacy::krypton::PPNStatusFromNSError(error), std::move(packets));
          PPNLog(@"[%p] Cancelling session due to read error: %@", strongSelf, error);
          [strongSelf->_session cancel];
          [strongSelf->_lock unlock];
          return;
        }

        for (NSData *datagram in datagrams) {
          packets.emplace_back(privacy::krypton::PacketFromNSData(datagram, strongSelf->_protocol));
        }
        if (!handler(absl::OkStatus(), std::move(packets))) {
          PPNLog(@"[%p] Cancelling session due to handler returning false.", strongSelf);
          [strongSelf->_session cancel];
          [strongSelf->_lock unlock];
          return;
        }

        [strongSelf->_lock unlock];
      }
        maxDatagrams:kMaxDatagrams];
}

- (absl::Status)writePackets:(std::vector<::privacy::krypton::Packet>)packets {
  // We can access the _session state directly here, since we aren't going to wait to see if it
  // changes. If it changes between now and writing, there's nothing we can do about it anyway.
  if (_session.state == NWUDPSessionStateFailed) {
    return absl::InternalError("UDP Session in failure state.");
  }
  if (_session.state == NWUDPSessionStateCancelled) {
    return absl::CancelledError("UDP Session in cancelled state.");
  }
  if (_session.state == NWUDPSessionStateInvalid) {
    return absl::InternalError("UDP Session in invalid state.");
  }

  // TODO: We should revisit this timeout check now that we have a dispatch queue
  // waiting on writes to complete. We can efficiently test each individual write.

  // This is a rough heuristic to determine when the pipe is stuck.
  // If the oldest write that hasn't completed is from too long ago, consider the pipe failed.
  double currentTime = [[NSDate date] timeIntervalSinceReferenceDate];
  if (currentTime - _lastWriteStartTime > kWriteTimeoutInterval) {
    return absl::DeadlineExceededError("Timeout in UDP Session write.");
  }

  // Now, this write may be the oldest write. We need a loop to handle race conditions.
  while (currentTime < _lastWriteStartTime) {
    _lastWriteStartTime = currentTime;
  }

  _writesStarted++;
  __weak PPNUDPSessionPipeWrapper *weakSelf = self;
  __block std::vector<::privacy::krypton::Packet> packetsRef = std::move(packets);
  NWUDPSession *session = _session;
  // TODO: Clean this up by not using a dispatch queue at all.
  dispatch_sync(_writeQueue, ^{
    if (_session.state != NWUDPSessionStateReady) {
      PPNLog(@"Dropping queued write, because UDP session was closed.");
      return;
    }
    NSMutableArray<NSData *> *datagrams = [NSMutableArray arrayWithCapacity:packetsRef.size()];
    for (const auto &packet : packetsRef) {
      NSData *data = NSDataFromPacketNoCopy(packet);
      [datagrams addObject:data];
    }
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [session writeMultipleDatagrams:datagrams
                  completionHandler:^(NSError *_Nullable error) {
                    dispatch_semaphore_signal(semaphore);

                    if (error != nil) {
                      PPNLog(@"Ignoring failed UDP session write with error %@", error);
                    }

                    PPNUDPSessionPipeWrapper *strongSelf = weakSelf;
                    if (strongSelf == nil) {
                      return;
                    }

                    strongSelf->_writesCompleted++;
                    if (error != nil) {
                      strongSelf->_writeErrors++;
                    }

                    // We need to mark that this write is done.
                    // Note that the write currently finishing may not actually be the oldest write.
                    // That's okay, because any newer write also means the pipe is still working.
                    // There is an edge case that we may ignore failed writes that happen
                    // concurrently with a successful write, but it's better to err on the side of
                    // keeping the pipe alive longer than to fail prematurely.
                    strongSelf->_lastWriteStartTime =
                        [[NSDate distantFuture] timeIntervalSinceReferenceDate];
                  }];
    dispatch_time_t timeout =
        dispatch_time(DISPATCH_TIME_NOW, kWriteTimeoutInterval * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
      LOG(ERROR) << "Timeout waiting for UDP write.";
    }
  });
  return absl::OkStatus();
}

- (void)close {
  [_lock lock];
  _stopped = YES;
  PPNLog(@"[%p] Cancelling session because it is being closed.", self);
  [_session cancel];
  [_lock unlock];
  PPN_LOG_IF_ERROR([self waitForCancellation]);
}

- (NSString *)description {
  return [NSString stringWithFormat:@"PPNUDPSessionPipe[%p](session=%@, stopped=%s)", self,
                                    _session, _stopped ? "YES" : "NO"];
}

- (void)getDebugInfo:(::privacy::krypton::PacketPipeDebugInfo *)debugInfo {
  debugInfo->set_writes_started(_writesStarted);
  debugInfo->set_writes_completed(_writesCompleted);
  debugInfo->set_write_errors(_writeErrors);
}

@end

namespace privacy {
namespace krypton {

PPNUDPSessionPipe::PPNUDPSessionPipe(NWUDPSession *session, IPProtocol protocol) {
  wrapper_ = [[PPNUDPSessionPipeWrapper alloc] initWithUDPSession:session protocol:protocol];
}

absl::Status PPNUDPSessionPipe::WaitForReady() { return [wrapper_ waitForReady]; }

absl::Status PPNUDPSessionPipe::WritePackets(std::vector<Packet> packets) {
  return [wrapper_ writePackets:std::move(packets)];
}

void PPNUDPSessionPipe::ReadPackets(
    std::function<bool(absl::Status status, std::vector<Packet> packet)> handler) {
  [wrapper_ readPackets:handler];
}

void PPNUDPSessionPipe::Close() { [wrapper_ close]; }

std::string PPNUDPSessionPipe::DebugString() { return wrapper_.description.UTF8String; }

void PPNUDPSessionPipe::GetDebugInfo(PacketPipeDebugInfo *debug_info) {
  [wrapper_ getDebugInfo:debug_info];
}

}  // namespace krypton
}  // namespace privacy
