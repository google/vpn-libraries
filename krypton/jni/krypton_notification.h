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

#ifndef PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_
#define PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_

#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace jni {

// All krypton notifications that are eventually plumbed through JNI.
class KryptonNotification : public KryptonNotificationInterface {
 public:
  KryptonNotification() = default;
  ~KryptonNotification() override = default;

  void Connected() override;
  void Connecting() override;
  void ControlPlaneConnected() override;
  void StatusUpdated() override;
  void Disconnected(const absl::Status& status) override;
  void PermanentFailure(const absl::Status& status) override;
  void NetworkDisconnected(const NetworkInfo& network_info,
                           const absl::Status& status) override;
  void Crashed() override;
  void WaitingToReconnect(const int64 retry_millis) override;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_
