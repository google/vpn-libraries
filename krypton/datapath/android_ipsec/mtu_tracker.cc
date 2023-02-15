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

#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker.h"

#include "base/logging.h"
#include "privacy/net/krypton/pal/packet.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

constexpr int kDefaultMtu = 1500;

constexpr int kAesGcm128Overhead = 27;  // 8 (IV) + 3 (Max pad) + 16 (ICV)

// Max ESP overhead possible for IPv4. 60 (Outer IPv4 + options) + 8 (UDP encap)
// + 4 (SPI) + 4 (Seq) + 2 (Pad Length + Next Header).
constexpr int kGenericEspOverheadMaxV4 = 78;

// Max ESP overhead possible for IPv6. 40 (Outer IPv6) + 4 (SPI) + 4 (Seq) + 2
// (Pad Length + Next Header).
constexpr int kGenericEspOverheadMaxV6 = 50;

constexpr int kMaxIpv4Overhead = kAesGcm128Overhead + kGenericEspOverheadMaxV4;
constexpr int kMaxIpv6Overhead = kAesGcm128Overhead + kGenericEspOverheadMaxV6;

MtuTracker::MtuTracker(IPProtocol dest_ip_protocol)
    : MtuTracker(dest_ip_protocol, kDefaultMtu) {}

MtuTracker::MtuTracker(IPProtocol dest_ip_protocol, int initial_path_mtu)
    : dest_ip_protocol_(dest_ip_protocol),
      tunnel_overhead_(dest_ip_protocol == IPProtocol::kIPv6
                           ? kMaxIpv6Overhead
                           : kMaxIpv4Overhead),
      path_mtu_(initial_path_mtu),
      tunnel_mtu_(path_mtu_ - tunnel_overhead_) {}

void MtuTracker::UpdateMtu(int path_mtu) {
  if (path_mtu < path_mtu_) {
    LOG(INFO) << "Updating Path MTU from " << path_mtu_ << " to " << path_mtu;
    path_mtu_ = path_mtu;
    int tunnel_mtu = path_mtu_ - tunnel_overhead_;
    LOG(INFO) << "Updating Tunnel MTU from " << tunnel_mtu_ << " to "
              << tunnel_mtu;
    tunnel_mtu_ = tunnel_mtu;
  }
}

int MtuTracker::GetPathMtu() const { return path_mtu_; }

int MtuTracker::GetTunnelMtu() const { return tunnel_mtu_; }

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
