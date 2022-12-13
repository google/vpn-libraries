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

#include "privacy/net/krypton/desktop/windows/ipc_ppn_service.h"

#include <cstddef>
#include <string>

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace windows {

IpcPpnService::~IpcPpnService() { Stop(); }

absl::Status IpcPpnService::PollOnPipe() {
  // If close event is in non signaled or non failure state, continue to poll.
  while (windows_api_->WaitForSingleObject(
             named_pipe_interface_->GetStopPipeEvent(), 0) == WAIT_TIMEOUT) {
    PPN_RETURN_IF_ERROR(ReadAndWriteToPipe());
  }
  return absl::CancelledError("Polling from app to service pipe cancelled");
}

absl::Status IpcPpnService::ReadAndWriteToPipe() {
  desktop::KryptonControlMessage request_message;
  PPN_ASSIGN_OR_RETURN(request_message,
                       named_pipe_interface_->IpcReadSyncMessage());
  LOG(INFO) << "Read the message of type " << request_message.type();

  // Does a deep copy of the returned response
  desktop::KryptonControlMessage response =
      ProcessAppToServiceMessage(request_message);

  PPN_RETURN_IF_ERROR(named_pipe_interface_->IpcSendSyncMessage(response));
  LOG(INFO) << "Sent a message of type " << response.type();
  return absl::OkStatus();
}

absl::StatusOr<desktop::KryptonControlMessage> IpcPpnService::CallPipe(
    desktop::KryptonControlMessage request) {
  if (windows_api_->WaitForSingleObject(
          named_pipe_interface_->GetStopPipeEvent(), 0) != WAIT_TIMEOUT) {
    return absl::CancelledError("Stop Event on Pipe is called");
  }
  LOG(INFO) << "Sending a message of type " << request.type();
  PPN_ASSIGN_OR_RETURN(desktop::KryptonControlMessage response,
                       named_pipe_interface_->Call(request));
  LOG(INFO) << "Received a message of type " << response.type();
  return response;
}

desktop::KryptonControlMessage IpcPpnService::ProcessAppToServiceMessage(
    desktop::KryptonControlMessage message) {
  absl::Status validate_message_status = ValidateRequest(message);
  desktop::KryptonControlMessage response;
  response.set_type(message.type());
  if (!validate_message_status.ok()) {
    google::rpc::Status status =
        utils::GetRpcStatusforStatus(validate_message_status);
    *(response.mutable_response()->mutable_status()) = status;
    return response;
  }
  google::rpc::Status* status = new google::rpc::Status();
  desktop::KryptonControlRequest request = message.request();
  switch (message.type()) {
    case desktop::KryptonControlMessage::NOTIFICATION_UPDATE: {
      HandleNotification(request, status);
      break;
    }
    case desktop::KryptonControlMessage::FETCH_OAUTH_TOKEN: {
      auto oauth_status = oauth_->GetOAuthToken();
      if (!oauth_status.ok()) {
        *status = utils::GetRpcStatusforStatus(oauth_status.status());
        break;
      }
      response.mutable_response()
          ->mutable_fetch_outh_token_response()
          ->set_oauth_token(*oauth_status);
      status->set_code(google::rpc::Code::OK);
      break;
    }
    default: {
      status->set_code(google::rpc::Code::INVALID_ARGUMENT);
      status->set_message("No valid message type present in the request");
      break;
    }
  }
  response.mutable_response()->set_allocated_status(status);
  return response;
}

absl::Status IpcPpnService::ValidateRequest(
    desktop::KryptonControlMessage message) {
  desktop::KryptonControlRequest request;
  switch (message.type()) {
    case desktop::KryptonControlMessage::NOTIFICATION_UPDATE:
      request = message.request();
      if (!request.has_notification_update_request()) {
        return absl::InvalidArgumentError(
            "Krypton Message Type doesn't match with the contents of "
            "message.");
      }
      switch (request.notification_update_request().notification_type()) {
        case desktop::NotificationUpdateRequest::PPN_DISCONNECTED:
          if (!request.notification_update_request()
                   .has_ppn_disconnection_status()) {
            return absl::InvalidArgumentError(
                "PPN Disconnected Notification should have a PPN "
                "Disconection "
                "Status.");
          }
          break;
        case desktop::NotificationUpdateRequest::PPN_STOPPED:
          if (!request.notification_update_request().has_ppn_stop_status()) {
            return absl::InvalidArgumentError(
                "PPN Stopped Notification should have a PPN Stopped Status.");
          }
          break;
        case desktop::NotificationUpdateRequest::PPN_PERMANENT_FAILURE:
          if (!request.notification_update_request()
                   .has_ppn_permanent_failure_status()) {
            return absl::InvalidArgumentError(
                "PPN Permanent Failure Notification should have a PPN "
                "Permanent Failure Status.");
          }
          break;
        case desktop::NotificationUpdateRequest::NOTIFICATION_TYPE_UNSPECIFIED:
          return absl::UnimplementedError(absl::Substitute(
              "This notification type $0 is not supported yet",
              request.notification_update_request().notification_type()));
        default:
          break;
      }
      return absl::OkStatus();
    case desktop::KryptonControlMessage::FETCH_OAUTH_TOKEN:
      return absl::OkStatus();
    default:
      return absl::UnimplementedError("This message type is not supported yet");
  }
}

void IpcPpnService::HandleNotification(desktop::KryptonControlRequest request,
                                       google::rpc::Status* status) {
  auto ppn_notification = ppn_notification_;
  LOG(INFO) << "Received a notification of type: "
            << request.notification_update_request().notification_type();
  switch (request.notification_update_request().notification_type()) {
    case desktop::NotificationUpdateRequest::PPN_DISCONNECTED: {
      ppn_notification_looper_->Post([ppn_notification, request] {
        ppn_notification->PpnDisconnected(request.notification_update_request()
                                              .ppn_disconnection_status()
                                              .status());
      });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_STOPPED: {
      ppn_notification_looper_->Post([ppn_notification, request] {
        ppn_notification->PpnStopped(utils::GetStatusFromRpcStatus(
            request.notification_update_request().ppn_stop_status().status()));
      });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_PERMANENT_FAILURE: {
      ppn_notification_looper_->Post([ppn_notification, request] {
        ppn_notification->PpnPermanentFailure(
            utils::GetStatusFromRpcStatus(request.notification_update_request()
                                              .ppn_permanent_failure_status()
                                              .status()));
      });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_STARTED: {
      ppn_notification_looper_->Post(
          [ppn_notification] { ppn_notification->PpnStarted(); });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_CONNECTED: {
      ppn_notification_looper_->Post(
          [ppn_notification] { ppn_notification->PpnConnected(); });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_CONNECTING: {
      ppn_notification_looper_->Post(
          [ppn_notification] { ppn_notification->PpnConnecting(); });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::NotificationUpdateRequest::PPN_WAITING_TO_RECONNECT: {
      ppn_notification_looper_->Post(
          [ppn_notification] { ppn_notification->PpnWaitingToReconnect(); });
      status->set_code(google::rpc::Code::OK);
      break;
    }
    default: {
      status->set_code(google::rpc::Code::UNIMPLEMENTED);
      status->set_message(absl::Substitute(
          "No valid notification type $0 present in the request",
          request.notification_update_request().notification_type()));
    }
  }
}

void IpcPpnService::Stop() {
  // Wait until all the messages are read
  named_pipe_interface_->FlushPipe();
  SetEvent(named_pipe_interface_->GetStopPipeEvent());
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
