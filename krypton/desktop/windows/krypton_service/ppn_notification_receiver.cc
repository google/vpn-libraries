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
#include "privacy/net/krypton/desktop/windows/krypton_service/ppn_notification_receiver.h"

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/log.h"

namespace privacy {
namespace krypton {
namespace windows {

void PpnNotificationReceiver::PpnStarted() {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_STARTED);
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnStopped(const absl::Status& status) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_STOPPED);
  google::rpc::Status rpc_status = utils::GetRpcStatusforStatus(status);
  *(notification_request.mutable_ppn_stop_status()->mutable_status()) =
      rpc_status;
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnConnected() {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_CONNECTED);
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnConnecting() {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_CONNECTING);
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnDisconnected(
    const privacy::krypton::DisconnectionStatus& status) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_DISCONNECTED);
  *(notification_request.mutable_ppn_disconnection_status()->mutable_status()) =
      status;
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnWaitingToReconnect() {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_WAITING_TO_RECONNECT);
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::PpnPermanentFailure(const absl::Status& status) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::NOTIFICATION_UPDATE);
  desktop::NotificationUpdateRequest notification_request;
  notification_request.set_notification_type(
      desktop::NotificationUpdateRequest::PPN_PERMANENT_FAILURE);
  google::rpc::Status rpc_status = utils::GetRpcStatusforStatus(status);
  *(notification_request.mutable_ppn_permanent_failure_status()
        ->mutable_status()) = rpc_status;
  *(request.mutable_request()->mutable_notification_update_request()) =
      notification_request;
  LOG(INFO) << "Sending a notification of type: "
            << notification_request.notification_type();
  ProcessNotificationResponse(notification_request.notification_type(),
                              ipc_handler_->CallPipe(request));
}

void PpnNotificationReceiver::ProcessNotificationResponse(
    desktop::NotificationUpdateRequest::NotificationType type,
    absl::StatusOr<desktop::KryptonControlMessage> response_status) {
  if (!response_status.ok()) {
    LOG(WARNING) << "Notification update of type " << type
                 << " failed to process due to " << response_status.status();
    return;
  }
  desktop::KryptonControlMessage response = *response_status;
  if (response.IsInitialized() &&
      response.response().status().code() != google::rpc::Code::OK) {
    LOG(WARNING) << "Notification update of type " << type
                 << " failed to process due to "
                 << response.response().status().SerializeAsString();
    return;
  }
  LOG(INFO) << "Notification update of type " << type
            << " processed successfully.";
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
