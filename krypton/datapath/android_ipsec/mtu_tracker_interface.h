// Copyright 2023 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_INTERFACE_H_

#include "privacy/net/krypton/pal/packet.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Interface which encapsulates bookkeeping around the maximum transmission unit
// (MTU) for a connection. Tracks both the Path MTU, for the network connection,
// and the Tunnel MTU, for the VPN Tunnel.
class MtuTrackerInterface {
 public:
  virtual ~MtuTrackerInterface() = default;

  // Updates both the Path MTU and Tunnel MTU based on a provided Path MTU.
  virtual void UpdateMtu(int path_mtu) = 0;

  // Updates the tunnel overhead used in MTU calculation based on the IP
  // protocol being connected to.
  virtual void UpdateDestIpProtocol(IPProtocol dest_ip_protocol) = 0;

  virtual int GetPathMtu() const = 0;

  virtual int GetTunnelMtu() const = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_INTERFACE_H_
