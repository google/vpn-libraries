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

#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class MssMtuDetectorInterface {
 public:
  enum class UpdateResult { kUpdated, kNotUpdated };
  struct MssMtuUpdateInfo {
    UpdateResult uplink;
    UpdateResult downlink;
  };

  virtual ~MssMtuDetectorInterface() = default;

  virtual absl::Status Start() = 0;

  virtual absl::StatusOr<MssMtuUpdateInfo> HandleEvent(
      const EventsHelper::Event& ev) = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_INTERFACE_H_
