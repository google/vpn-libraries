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

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "third_party/absl/status/status.h"

@class PPNPacketForwarder;

namespace privacy {
namespace krypton {

class PacketForwarderNotificationInterface {
 public:
  PacketForwarderNotificationInterface() = default;
  virtual ~PacketForwarderNotificationInterface() = default;

  // Datapath failed with status.
  // NOTE: Clients should call stop after receiving this notification.
  virtual void PacketForwarderFailed(const absl::Status &) = 0;

  // Permanent Datapath failure
  // NOTE: Clients should call stop after receiving this notification.
  virtual void PacketForwarderPermanentFailure(const absl::Status &) = 0;

  // PacketForwarder did successfully forward one packet since Start was called.
  virtual void PacketForwarderConnected() = 0;

  // Datapath should recreate the PacketForwarder with a new session.
  virtual void PacketForwarderHasBetterPath(NWUDPSession *) = 0;
};

}  // namespace krypton
}  // namespace privacy

@interface PPNPacketForwarder : NSObject

// Creates and starts the packet forwarder.
- (instancetype)
        initWithConfig:(const privacy::krypton::KryptonConfig &)config
             encryptor:(std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecEncryptor>)encryptor
             decryptor:(std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecDecryptor>)decryptor
      packetTunnelFlow:(NEPacketTunnelFlow *)packetTunnelFlow
               session:(NWUDPSession *)session
          notification:(privacy::krypton::PacketForwarderNotificationInterface *)notification
    notificationLooper:(privacy::krypton::utils::LooperThread *)notificationLooper;

- (void)start;

- (void)stop;

- (void)collectDebugInfo:(privacy::krypton::DatapathDebugInfo *)debugInfo;

@end
