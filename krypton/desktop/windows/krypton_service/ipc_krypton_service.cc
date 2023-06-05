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
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

IpcKryptonService::~IpcKryptonService() { Stop(); }

desktop::KryptonControlMessage IpcKryptonService::ProcessKryptonControlMessage(
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
  switch (message.type()) {
    case desktop::KryptonControlMessage::START_KRYPTON: {
      const KryptonConfig& config =
          message.request().start_krypton_request().krypton_config();
      ppn_service_->Start(config);
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::KryptonControlMessage::STOP_KRYPTON: {
      const absl::Status stop_status = utils::GetStatusFromRpcStatus(
          message.request().stop_krypton_request().status());
      ppn_service_->Stop(stop_status);
      status->set_code(google::rpc::Code::OK);
      break;
    }
    case desktop::KryptonControlMessage::COLLECT_TELEMETRY: {
      auto ppn_telemetry = ppn_service_->CollectTelemetry();
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
    case desktop::KryptonControlMessage::SET_IP_GEO_LEVEL: {
      auto level = message.request().set_ip_geo_level_request().level();
      auto set_status = ppn_service_->SetIpGeoLevel(level);
      if (!set_status.ok()) {
        status->set_code(google::rpc::Code::INTERNAL);
        status->set_message(set_status.message());
        break;
      }
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
    case desktop::KryptonControlMessage::SET_IP_GEO_LEVEL:
      request = message.request();
      if (!request.has_set_ip_geo_level_request())
        return absl::InternalError(
            "Krypton Message Type doesn't match with the contents of message.");
      if (!request.set_ip_geo_level_request().has_level()) {
        return absl::InternalError(
            "No ip geo level passed to Krypton SetIpGeoLevel Message.");
      }
      return absl::OkStatus();
    default:
      return absl::UnimplementedError("This message type is not supported yet");
  }
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
