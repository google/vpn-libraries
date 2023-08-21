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

#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/log/die_if_null.h"
#include "third_party/absl/log/log.h"

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

MtuTracker::MtuTracker(IPProtocol dest_ip_protocol,
                       NotificationInterface* notification,
                       utils::LooperThread* notification_thread)
    : MtuTracker(dest_ip_protocol, kDefaultMtu, notification,
                 notification_thread) {}

MtuTracker::MtuTracker(IPProtocol dest_ip_protocol, int initial_path_mtu,
                       NotificationInterface* notification,
                       utils::LooperThread* notification_thread)
    : tunnel_overhead_(dest_ip_protocol == IPProtocol::kIPv6
                           ? kMaxIpv6Overhead
                           : kMaxIpv4Overhead),
      uplink_mtu_(initial_path_mtu),
      tunnel_mtu_(uplink_mtu_ - tunnel_overhead_),
      downlink_mtu_(initial_path_mtu),
      notification_(ABSL_DIE_IF_NULL(notification)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)) {
  // Send the current values to the new NotificationHandler
  notification_thread_->Post([notification, downlink_mtu = downlink_mtu_,
                              uplink_mtu = uplink_mtu_,
                              tunnel_mtu = tunnel_mtu_] {
    notification->DownlinkMtuUpdated(downlink_mtu);
    notification->UplinkMtuUpdated(uplink_mtu, tunnel_mtu);
  });
}

void MtuTracker::UpdateUplinkMtu(int uplink_mtu) {
  if (uplink_mtu < uplink_mtu_) {
    LOG(INFO) << "Updating Path MTU from " << uplink_mtu_ << " to "
              << uplink_mtu;
    uplink_mtu_ = uplink_mtu;
    int tunnel_mtu = uplink_mtu_ - tunnel_overhead_;
    LOG(INFO) << "Updating Tunnel MTU from " << tunnel_mtu_ << " to "
              << tunnel_mtu;
    tunnel_mtu_ = tunnel_mtu;

    auto notification = notification_;
    notification_thread_->Post([notification, uplink_mtu, tunnel_mtu] {
      notification->UplinkMtuUpdated(uplink_mtu, tunnel_mtu);
    });
  }
}

void MtuTracker::UpdateDownlinkMtu(int downlink_mtu) {
  if (downlink_mtu < downlink_mtu_) {
    downlink_mtu_ = downlink_mtu;

    auto notification = notification_;
    notification_thread_->Post([notification, downlink_mtu] {
      notification->DownlinkMtuUpdated(downlink_mtu);
    });
  }
}

int MtuTracker::GetTunnelMtu() const { return tunnel_mtu_; }

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
