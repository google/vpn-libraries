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
#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_PPN_NOTIFICATION_RECEIVER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_PPN_NOTIFICATION_RECEIVER_H_

// Acts as a wrapper between Plugin and other services like Oauth, PpnService.
#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_krypton_service.h"
#include "privacy/net/krypton/desktop/windows/ppn_notification_interface.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

class PpnNotificationReceiver : public PpnNotificationInterface {
 public:
  explicit PpnNotificationReceiver(IpcKryptonService* ipc_handler)
      : ipc_handler_(ipc_handler) {}
  ~PpnNotificationReceiver() override = default;

  void PpnStarted() override;

  void PpnStopped(const absl::Status& status) override;

  void PpnConnected() override;

  void PpnConnecting() override;

  void PpnDisconnected(
      const privacy::krypton::DisconnectionStatus& status) override;

  void PpnWaitingToReconnect() override;

  void PpnPermanentFailure(const absl::Status& status) override;

 private:
  IpcKryptonService* ipc_handler_;

  void ProcessNotificationResponse(
      desktop::NotificationUpdateRequest::NotificationType type,
      absl::StatusOr<desktop::KryptonControlMessage> response_status);
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_PPN_NOTIFICATION_RECEIVER_H_
