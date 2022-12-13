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

#include "privacy/net/krypton/desktop/windows/notification.h"

#include "base/logging.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

void Notification::Connected(const ConnectionStatus& status) {
  LOG(INFO) << "PPN is connected: " << status.DebugString();
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post(
      [ppn_notification] { ppn_notification->PpnConnected(); });
  ppn_telemetry_manager_->NotifyConnected();
}

void Notification::Connecting(const ConnectingStatus& status) {
  LOG(INFO) << "PPN is connecting: " << status.DebugString();
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post(
      [ppn_notification] { ppn_notification->PpnConnecting(); });
}

void Notification::ControlPlaneConnected() {
  LOG(INFO) << "ControlPlaneConnected event";
}

void Notification::StatusUpdated(const ConnectionStatus& status) {
  LOG(ERROR) << "PPN status updated: " << status.DebugString();
}

void Notification::Disconnected(const DisconnectionStatus& status) {
  LOG(ERROR) << "PPN is disconnected: " << status.DebugString();
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post([ppn_notification, status] {
    ppn_notification->PpnDisconnected(status);
  });
  ppn_telemetry_manager_->NotifyDisconnected();
}

void Notification::NetworkDisconnected(const NetworkInfo& /* network_info */,
                                       const absl::Status& status) {
  LOG(ERROR) << "PPN's network is disconnected: " << status;
}

void Notification::PermanentFailure(const absl::Status& status) {
  LOG(ERROR) << "PPN failed: " << status;
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post([ppn_notification, status] {
    ppn_notification->PpnPermanentFailure(status);
  });
}

void Notification::Crashed() { LOG(ERROR) << "PPN is crashing."; }

void Notification::Snoozed(const SnoozeStatus& status) {
  LOG(INFO) << "PPN is snoozed: " << status.DebugString();
}

void Notification::Resumed(const ResumeStatus& status) {
  LOG(INFO) << "Ppn is resumed: " << status.DebugString();
}

void Notification::WaitingToReconnect(const ReconnectionStatus& status) {
  LOG(INFO) << "WaitingToReconnect event: " << status.DebugString();
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post(
      [ppn_notification] { ppn_notification->PpnWaitingToReconnect(); });
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
