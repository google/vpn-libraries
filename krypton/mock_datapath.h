// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_MOCK_DATAPATH_H_
#define PRIVACY_NET_KRYPTON_MOCK_DATAPATH_H_

#include "privacy/net/krypton/datapath_interface.h"
#include "testing/base/public/gmock.h"

namespace privacy {
namespace krypton {

// Mock the datapath interface for testing.
class MockDatapath : public DatapathInterface {
 public:
  MOCK_METHOD(absl::Status, Start,
              (std::shared_ptr<AddEgressResponse>, const BridgeTransformParams&,
               CryptoSuite),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, is_running, (), (const, override));
  MOCK_METHOD(void, RegisterNotificationHandler,
              (DatapathInterface::NotificationInterface * notification),
              (override));
  MOCK_METHOD(absl::Status, SwitchNetwork,
              (uint32, const std::vector<std::string>&,
               absl::optional<NetworkInfo>, const PacketPipe*,
               const PacketPipe*, int, VpnServiceInterface* vpn_service),
              (override));
  MOCK_METHOD(void, SetKeyMaterial, (const TransformParams&), (override));
  MOCK_METHOD(absl::Status, Rekey, (const std::string&, const std::string&),
              (override));
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_MOCK_DATAPATH_H_
