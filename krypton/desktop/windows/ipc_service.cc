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

#include "privacy/net/krypton/desktop/windows/ipc_service.h"

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

IpcService::~IpcService() { Stop(); }

absl::Status IpcService::PollOnPipe() {
  // If close event is in non signaled or non failure state, continue to poll.
  while (windows_api_->WaitForSingleObject(
             named_pipe_interface_->GetStopPipeEvent(), 0) == WAIT_TIMEOUT) {
    PPN_RETURN_IF_ERROR(ReadAndWriteToPipe());
  }
  return absl::CancelledError("Polling from app to service pipe cancelled");
}

absl::Status IpcService::ReadAndWriteToPipe() {
  desktop::KryptonControlMessage request_message;
  PPN_ASSIGN_OR_RETURN(request_message,
                       named_pipe_interface_->IpcReadSyncMessage());
  LOG(INFO) << "Read the message of type " << request_message.type();

  // Does a deep copy of the returned response
  desktop::KryptonControlMessage response =
      ProcessKryptonControlMessage(request_message);

  PPN_RETURN_IF_ERROR(named_pipe_interface_->IpcSendSyncMessage(response));
  LOG(INFO) << "Sent a message of type " << response.type();
  return absl::OkStatus();
}

absl::StatusOr<desktop::KryptonControlMessage> IpcService::CallPipe(
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

void IpcService::Stop() {
  // This is for safe execution in case named_pipe_interface_ is destroyed
  // before Stop() is called.
  if (named_pipe_interface_ == nullptr) return;
  // Wait until all the messages are read
  named_pipe_interface_->FlushPipe();
  SetEvent(named_pipe_interface_->GetStopPipeEvent());
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
