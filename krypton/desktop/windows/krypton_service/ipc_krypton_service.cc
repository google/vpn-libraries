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

#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_krypton_service.h"

#include <cstddef>
#include <string>

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/ppn_service_interface.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::Status IpcKryptonService::PollOnPipe(PpnServiceInterface* service) {
  // If close event is in non signaled or non failure state, continue to poll.
  while (windows_api_->WaitForSingleObject(
             named_pipe_interface_->GetStopPipeEvent(), 0) == WAIT_TIMEOUT) {
    // TODO: Refactor IpcHandler code across krypton service and
    // ppn service.
    PPN_RETURN_IF_ERROR(ReadAndWriteToPipe(service));
  }
  return absl::CancelledError("Polling from app to service pipe cancelled");
}

absl::Status IpcKryptonService::ReadAndWriteToPipe(
    PpnServiceInterface* service) {
  desktop::KryptonControlMessage request_message;
  PPN_ASSIGN_OR_RETURN(request_message,
                       named_pipe_interface_->IpcReadSyncMessage());
  LOG(INFO) << "Read the message of type " << request_message.type();

  // Does a deep copy of the returned response
  desktop::KryptonControlMessage response =
      ProcessAppToServiceMessage(service, request_message);

  PPN_RETURN_IF_ERROR(named_pipe_interface_->IpcSendSyncMessage(response));
  LOG(INFO) << "Sent a message of type " << response.type();
  return absl::OkStatus();
}

absl::StatusOr<desktop::KryptonControlMessage> IpcKryptonService::CallPipe(
    desktop::KryptonControlMessage request) {
  if (windows_api_->WaitForSingleObject(
          named_pipe_interface_->GetStopPipeEvent(), 0) != WAIT_TIMEOUT) {
    return absl::CancelledError("Stop Event on Pipe is called");
  }
  PPN_ASSIGN_OR_RETURN(desktop::KryptonControlMessage response,
                       named_pipe_interface_->Call(request));
  return response;
}

desktop::KryptonControlMessage IpcKryptonService::ProcessAppToServiceMessage(
    PpnServiceInterface* service, desktop::KryptonControlMessage message) {
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
  switch (message.type()) {
    case desktop::KryptonControlMessage::START_KRYPTON: {
      const KryptonConfig& config =
          message.request().start_krypton_request().krypton_config();
      service->Start(config);
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::KryptonControlMessage::STOP_KRYPTON: {
      const absl::Status stop_status = utils::GetStatusFromRpcStatus(
          message.request().stop_krypton_request().status());
      service->Stop(stop_status);
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::KryptonControlMessage::COLLECT_TELEMETRY: {
      auto ppn_telemetry = service->CollectTelemetry();
      if (!ppn_telemetry.ok()) {
        status->set_code(google::rpc::Code::INTERNAL);
        status->set_message(ppn_telemetry.status().message());
        break;
      }
      status->set_code(google::rpc::Code::OK);
      *(response.mutable_response()
            ->mutable_collect_telemetry_response()
            ->mutable_ppn_telemetry()) = *ppn_telemetry;
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

absl::Status IpcKryptonService::ValidateRequest(
    desktop::KryptonControlMessage message) {
  desktop::KryptonControlRequest request;
  switch (message.type()) {
    case desktop::KryptonControlMessage::START_KRYPTON:
      request = message.request();
      if (!request.has_start_krypton_request())
        return absl::InternalError(
            "Krypton Message Type doesn't match with the contents of message.");
      if (!request.start_krypton_request().has_krypton_config()) {
        return absl::InternalError(
            "Krypton Start Message doesn't have the necessary configs to start "
            "krypton.");
      }
      return absl::OkStatus();
    case desktop::KryptonControlMessage::STOP_KRYPTON:
      request = message.request();
      if (!request.has_stop_krypton_request())
        return absl::InternalError(
            "Krypton Message Type doesn't match with the contents of message.");
      if (!request.stop_krypton_request().has_status()) {
        return absl::InternalError(
            "Krypton Stop Message doesn't have status to stop krypton.");
      }
      return absl::OkStatus();
    case desktop::KryptonControlMessage::COLLECT_TELEMETRY:
      return absl::OkStatus();
    default:
      return absl::UnimplementedError("This message type is not supported yet");
  }
}

void IpcKryptonService::Stop() {
  if (named_pipe_interface_ == nullptr) return;
  SetEvent(named_pipe_interface_->GetStopPipeEvent());
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
