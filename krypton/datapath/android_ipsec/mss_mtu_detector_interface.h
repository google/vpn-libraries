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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_INTERFACE_H_

#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class MssMtuDetectorInterface {
 public:
  class NotificationInterface {
   public:
    virtual ~NotificationInterface() = default;

    virtual void MssMtuSuccess(int uplink_mss_mtu, int downlink_mss_mtu) = 0;

    virtual void MssMtuFailure(absl::Status status) = 0;
  };

  enum class UpdateResult { kUpdated, kNotUpdated };
  struct MssMtuUpdateInfo {
    UpdateResult uplink;
    UpdateResult downlink;
  };

  virtual ~MssMtuDetectorInterface() = default;

  virtual void Start(NotificationInterface* notification,
                     utils::LooperThread* notification_thread) = 0;

  virtual void Stop() = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_INTERFACE_H_
