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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNVPNSERVICE_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNVPNSERVICE_H_

#import <NetworkExtension/NetworkExtension.h>

#include <memory>

#include "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNDatapath.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/synchronization/mutex.h"

@protocol PPNUDPSessionManaging;
@protocol PPNVirtualNetworkInterfaceManaging;

namespace privacy {
namespace krypton {

class PPNVPNService : public datapath::ipsec::IpSecDatapath::IpSecVpnServiceInterface,
                      public PPNDatapath::PPNDatapathVpnServiceInterface {
 public:
  explicit PPNVPNService(id<PPNUDPSessionManaging> UDPSessionManager,
                         id<PPNVirtualNetworkInterfaceManaging> networkManager)
      : UDPSessionManager_(UDPSessionManager), networkManager_(networkManager) {}

  ~PPNVPNService() override {}

  DatapathInterface* BuildDatapath(const KryptonConfig& config, utils::LooperThread* looper,
                                   TimerManager* timer_manager) override;
  // Establishes the tunnel.
  absl::Status CreateTunnel(const TunFdData& tun_fd_data) override;
  PacketPipe* GetTunnel() override;
  NEPacketTunnelFlow* GetPacketTunnelFlow() override;
  void CloseTunnel() override;

  // Create aa udp session to a given endpoint.
  absl::StatusOr<NWUDPSession*> CreateUDPSession(const NetworkInfo& network_info,
                                                 const Endpoint& endpoint) override;

  // Creates a network side packet pipe using the `endpoint`.
  absl::StatusOr<std::unique_ptr<PacketPipe>> CreateNetworkPipe(const NetworkInfo& network_info,
                                                                const Endpoint& endpoint) override;

  // Verifies the tunnel connection is still up.
  absl::Status CheckConnection() override;

 private:
  // Objective-C function manager that is used to create a UDP session upon demand.
  //
  // `__weak` is used to break the reference cycle introduced by Objective-C's
  // ARC system.
  //
  // Tunnel provider class guarantees the UDPSessionManager_'s lifespan is at least the
  // same as this class. The graph of the reference:
  // TunnelProvider -> PPNService -> PPNKryptonService -> PPNVPNService
  //       ^                                                    |
  //       | _ _ _ _ _ _ _ _ PPNUDPSessionManaging _ _ _ _ _ _ _|
  __weak id<PPNUDPSessionManaging> UDPSessionManager_;
  __weak id<PPNVirtualNetworkInterfaceManaging> networkManager_;

  absl::Mutex mutex_;
  TunFdData tun_fd_data_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<PacketPipe> tunnel_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNVPNSERVICE_H_
