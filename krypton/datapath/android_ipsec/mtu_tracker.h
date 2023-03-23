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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_H_

#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class MtuTracker : public MtuTrackerInterface {
 public:
  explicit MtuTracker(IPProtocol dest_ip_protocol);
  MtuTracker(IPProtocol dest_ip_protocol, int initial_uplink_mtu);

  void UpdateUplinkMtu(int uplink_mtu) override;

  void UpdateDownlinkMtu(int downlink_mtu) override;

  int GetUplinkMtu() const override;

  int GetTunnelMtu() const override;

  int GetDownlinkMtu() const override;

  void RegisterNotificationHandler(
      NotificationInterface* notification,
      utils::LooperThread* notification_thread) override;

 private:
  int tunnel_overhead_;
  int uplink_mtu_;
  int tunnel_mtu_;
  int downlink_mtu_;

  NotificationInterface* notification_;  // Not owned.

  // This thread will be used to send notifications "up the stack" to listeners.
  // It should not be used for anything else.
  utils::LooperThread* notification_thread_;  // Not owned.
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_H_
