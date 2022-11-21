// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_

#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"

// Interface for Krypton to interact with the system-level VPN service API.
namespace privacy {
namespace krypton {

class VpnServiceInterface {
 public:
  VpnServiceInterface() = default;
  virtual ~VpnServiceInterface() = default;

  // Builds a network-side pipe that reads and writes packets.
  virtual DatapathInterface* BuildDatapath(const KryptonConfig& config,
                                           utils::LooperThread* looper,
                                           TimerManager* timer_manager) = 0;

  // Creates the tunnel with the given network settings.
  // If there's already a tunnel open, this will close it after creating the new
  // tunnel, if applicable. If there's an error, the old tunnel will still be in
  // place, on platforms that allow it.
  virtual absl::Status CreateTunnel(const TunFdData& tun_fd_data) = 0;

  // Closes the current tunnel, disestablishing the VPN.
  virtual void CloseTunnel() = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_
