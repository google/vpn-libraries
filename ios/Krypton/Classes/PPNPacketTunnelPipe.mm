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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketTunnelPipe.h"

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacket.h"
#import "privacy/net/krypton/utils/status.h"
#import "third_party/absl/status/status.h"
#import "third_party/absl/strings/str_cat.h"

// A simple wrapper around a mutable boolean. This can be used to signal to a block that captures
// it if the original caller wants the operation to be ignored when the block is called.
// This class is not threadsafe. Its use needs to be coordinated with other state in the classes
// that use it, so they can manage its threadsafety.
@interface PPNCancellationToken : NSObject
@property(nonatomic, assign, getter=isCancelled) BOOL cancelled;
@end

@implementation PPNCancellationToken
@end

// A wrapper around the calls to the packet pipe to deal with the fact that iOS might call the read
// callback after the object has been destroyed.
@interface PPNPacketTunnelPipeWrapper : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithTunnelFlow:(NEPacketTunnelFlow *)flow NS_DESIGNATED_INITIALIZER;

- (void)readPackets:
    (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler;

- (void)readPacketsRecursively:
            (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler
             cancellationToken:(PPNCancellationToken *)cancellationToken;

- (absl::Status)writePackets:(std::vector<::privacy::krypton::Packet>)packet;

@end

@implementation PPNPacketTunnelPipeWrapper {
  NEPacketTunnelFlow *_packetTunnelFlow;
  PPNCancellationToken *_currentCancellationToken;
  NSLock *_lock;
}

- (instancetype)initWithTunnelFlow:(NEPacketTunnelFlow *)flow {
  self = [super init];
  if (self != nil) {
    _packetTunnelFlow = flow;
    _currentCancellationToken = nil;
    _lock = [[NSLock alloc] init];
  }
  return self;
}

- (void)stopReadingPackets {
  [_lock lock];
  _currentCancellationToken.cancelled = YES;
  _currentCancellationToken = nil;
  [_lock unlock];
}

- (void)readPackets:
    (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler {
  [_lock lock];

  if (_currentCancellationToken != nil) {
    LOG(WARNING) << "PPNPacketTunnelPipe readPackets was called twice without stopping in between.";
    _currentCancellationToken.cancelled = YES;
  }
  PPNCancellationToken *token = [[PPNCancellationToken alloc] init];
  _currentCancellationToken = token;

  [_lock unlock];
  [self readPacketsRecursively:handler cancellationToken:token];
}

- (void)readPacketsRecursively:
            (std::function<bool(absl::Status, std::vector<::privacy::krypton::Packet>)>)handler
             cancellationToken:(PPNCancellationToken *)cancellationToken {
  __weak PPNPacketTunnelPipeWrapper *weakSelf = self;
  [_packetTunnelFlow readPacketObjectsWithCompletionHandler:^(NSArray<NEPacket *> *objc_packets) {
    // If the PPNPacketTunnelPipe that owns this wrapper is deleted, then this wrapper can be set to
    // nil. If that happens, then we should stop calling the handler.
    PPNPacketTunnelPipeWrapper *strongSelf = weakSelf;
    if (strongSelf == nil) {
      return;
    }

    std::vector<::privacy::krypton::Packet> packets;
    packets.reserve(objc_packets.count);
    for (NEPacket *objc_packet in objc_packets) {
      // Create a new packet.
      auto packet = privacy::krypton::PacketFromNEPacket(objc_packet);
      packets.emplace_back(std::move(packet));
    }

    // Hold the lock while calling the handler, so that we can guarantee that stopReadingPackets()
    // will block until the last handler is done executing.
    [strongSelf->_lock lock];
    if (cancellationToken.isCancelled) {
      LOG(INFO) << "PPNPacketTunnelPipe is stopped: " << strongSelf.description.UTF8String;
      [strongSelf->_lock unlock];
      return;
    }
    if (!handler(absl::OkStatus(), std::move(packets))) {
      [strongSelf->_lock unlock];
      return;
    }
    [strongSelf->_lock unlock];

    // Recursively loop until iOS breaks the cycle by not calling the completion handler above.
    // Note that this won't explode the stack, because iOS calls the handler on a background queue.
    [strongSelf readPacketsRecursively:handler cancellationToken:cancellationToken];
  }];
}

- (absl::Status)writePackets:(std::vector<::privacy::krypton::Packet>)packets {
  NSMutableArray<NEPacket *> *objc_packets = [NSMutableArray arrayWithCapacity:packets.size()];
  for (const auto &packet : packets) {
    NEPacket *objc_packet = ::privacy::krypton::NEPacketFromPacketNoCopy(packet);
    [objc_packets addObject:objc_packet];
  }
  if ([_packetTunnelFlow writePacketObjects:objc_packets]) {
    return absl::OkStatus();
  }
  return absl::UnknownError(absl::StrCat("Unable to write packets: ", strerror(errno)));
}

- (NSString *)description {
  return [NSString stringWithFormat:@"PPNPacketTunnelPipe(flow=%@)", _packetTunnelFlow];
}

@end

namespace privacy {
namespace krypton {

PPNPacketTunnelPipe::PPNPacketTunnelPipe(NEPacketTunnelFlow *packet_tunnel_flow)
    : wrapper_([[PPNPacketTunnelPipeWrapper alloc] initWithTunnelFlow:packet_tunnel_flow]) {}

PPNPacketTunnelPipe::PPNPacketTunnelPipe(PPNPacketTunnelPipe &&other) {
  wrapper_ = other.wrapper_;
  other.wrapper_ = nil;
}

PPNPacketTunnelPipe &PPNPacketTunnelPipe::operator=(PPNPacketTunnelPipe &&other) {
  wrapper_ = other.wrapper_;
  other.wrapper_ = nil;
  return *this;
}

absl::Status PPNPacketTunnelPipe::WritePackets(std::vector<Packet> packets) {
  return [wrapper_ writePackets:std::move(packets)];
}

void PPNPacketTunnelPipe::Close() { PPN_LOG_IF_ERROR(StopReadingPackets()); }

absl::Status PPNPacketTunnelPipe::StopReadingPackets() {
  LOG(INFO) << "Stopping PacketTunnelPipe...";
  [wrapper_ stopReadingPackets];
  return absl::OkStatus();
}

/**
 * Recursively loops reading packets until iOS decides to stop calling the callback with new
 * packets, or until Stop() is called. After calling Stop(), this method will eventually stop
 * being called.
 */
void PPNPacketTunnelPipe::ReadPackets(
    std::function<bool(absl::Status, std::vector<Packet>)> handler) {
  [wrapper_ readPackets:handler];
}

std::string PPNPacketTunnelPipe::DebugString() { return wrapper_.description.UTF8String; }

}  // namespace krypton
}  // namespace privacy
