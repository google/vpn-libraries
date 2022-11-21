// Copyright 2022 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_TUNNEL_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_TUNNEL_H_

#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "testing/base/public/gmock.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class MockTunnel : public TunnelInterface {
 public:
  MOCK_METHOD(absl::Status, Close, (), (override));
  MOCK_METHOD(absl::Status, CancelReadPackets, (), (override));
  MOCK_METHOD(absl::StatusOr<std::vector<Packet>>, ReadPackets, (), (override));
  MOCK_METHOD(absl::Status, WritePackets, (std::vector<Packet>), (override));
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_TUNNEL_H_
