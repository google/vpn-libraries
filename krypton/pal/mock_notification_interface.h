// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_PAL_MOCK_NOTIFICATION_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_MOCK_NOTIFICATION_INTERFACE_H_

#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "testing/base/public/gmock.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {

// Mock interface for Notification.  Used for testing.
class MockNotification : public KryptonNotificationInterface {
 public:
  MOCK_METHOD(void, Connected, (), (override));
  MOCK_METHOD(void, Connecting, (), (override));
  MOCK_METHOD(void, ControlPlaneConnected, (), (override));
  MOCK_METHOD(void, StatusUpdated, (), (override));
  MOCK_METHOD(void, Disconnected, (const absl::Status&), (override));
  MOCK_METHOD(void, PermanentFailure, (const absl::Status&), (override));
  MOCK_METHOD(void, NetworkDisconnected,
              (const NetworkInfo& network_info, const absl::Status&),
              (override));
  MOCK_METHOD(void, Crashed, (), (override));
  MOCK_METHOD(void, WaitingToReconnect, (const int64 retry_millis), (override));
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_MOCK_NOTIFICATION_INTERFACE_H_
