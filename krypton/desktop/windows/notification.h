/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NOTIFICATION_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NOTIFICATION_H_

#include <cstdint>
#include <functional>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/ppn_notification_interface.h"
#include "privacy/net/krypton/desktop/windows/ppn_telemetry_manager.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

class Notification : public privacy::krypton::KryptonNotificationInterface {
 public:
  explicit Notification(PpnNotificationInterface* ppn_notification,
                        krypton::utils::LooperThread* ppn_notification_looper,
                        PpnTelemetryManager* ppn_telemetry_manager)
      : ppn_notification_(ppn_notification),
        ppn_notification_looper_(ppn_notification_looper),
        ppn_telemetry_manager_(ppn_telemetry_manager) {}
  ~Notification() override = default;

  void Connected(const privacy::krypton::ConnectionStatus& status) override;

  void Connecting(const privacy::krypton::ConnectingStatus& status) override;

  void ControlPlaneConnected() override;

  void StatusUpdated(const privacy::krypton::ConnectionStatus& status) override;

  void Disconnected(
      const privacy::krypton::DisconnectionStatus& status) override;

  void NetworkDisconnected(const privacy::krypton::NetworkInfo& network_info,
                           const absl::Status& status) override;

  void PermanentFailure(const absl::Status& status) override;

  void Crashed() override;

  void Snoozed(const privacy::krypton::SnoozeStatus& status) override;

  void Resumed(const privacy::krypton::ResumeStatus& status) override;

  void WaitingToReconnect(
      const privacy::krypton::ReconnectionStatus& status) override;

 private:
  PpnNotificationInterface* ppn_notification_;
  krypton::utils::LooperThread* ppn_notification_looper_;
  PpnTelemetryManager* ppn_telemetry_manager_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NOTIFICATION_H_
