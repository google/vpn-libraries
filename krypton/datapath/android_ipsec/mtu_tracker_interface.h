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

#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Interface which encapsulates bookkeeping around the maximum transmission unit
// (MTU) for a connection. Tracks the uplink MTU, downlink MTU, and tunnel MTU.
// The uplink MTU is from the client to the backend, the downlink MTU is from
// the backend to the client, and the tunnel MTU is from the TUN interface to
// the network.
class MtuTrackerInterface {
 public:
  class NotificationInterface {
   public:
    virtual ~NotificationInterface() = default;

    virtual void UplinkMtuUpdated(int uplink_mtu, int tunnel_mtu) = 0;

    virtual void DownlinkMtuUpdated(int downlink_mtu) = 0;
  };

  virtual ~MtuTrackerInterface() = default;

  // Updates both the uplink MTU and tunnel MTU based on the uplink MTU value.
  virtual void UpdateUplinkMtu(int uplink_mtu) = 0;

  virtual void UpdateDownlinkMtu(int downlink_mtu) = 0;

  virtual int GetTunnelMtu() const = 0;

  virtual void RegisterNotificationHandler(
      NotificationInterface* notification,
      utils::LooperThread* notification_thread) = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MTU_TRACKER_INTERFACE_H_
