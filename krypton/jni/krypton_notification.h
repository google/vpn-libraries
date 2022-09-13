// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_
#define PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_

#include <jni.h>

#include <cstdint>
#include <memory>

#include "base/logging.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace jni {

// All krypton notifications that are eventually plumbed through JNI.
class KryptonNotification : public KryptonNotificationInterface {
 public:
  explicit KryptonNotification(jobject krypton_instance)
      : krypton_instance_(std::make_unique<JavaObject>(krypton_instance)) {}
  ~KryptonNotification() override = default;

  void Connected(const ConnectionStatus& status) override;
  void Connecting(const ConnectingStatus& status) override;
  void ControlPlaneConnected() override;
  void StatusUpdated(const ConnectionStatus& status) override;
  void Disconnected(const DisconnectionStatus& status) override;
  void PermanentFailure(const absl::Status& status) override;
  void NetworkDisconnected(const NetworkInfo& network_info,
                           const absl::Status& status) override;
  void Crashed() override;
  void WaitingToReconnect(const ReconnectionStatus& status) override;
  void Snoozed(const SnoozeStatus& status) override;
  void Resumed(const ResumeStatus& status) override;

 private:
  std::unique_ptr<JavaObject> krypton_instance_;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_KRYPTON_NOTIFICATION_H_
