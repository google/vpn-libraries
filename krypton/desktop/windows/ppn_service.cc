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

#include "privacy/net/krypton/desktop/windows/ppn_service.h"

#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/desktop_oauth_interface.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/http_fetcher.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory_interface.h"
#include "privacy/net/krypton/desktop/windows/ipc_ppn_service.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/constants.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api.h"
#include "privacy/net/krypton/desktop/windows/krypton_service_manager.h"
#include "privacy/net/krypton/desktop/windows/ppn_notification_interface.h"
#include "privacy/net/krypton/desktop/windows/timer.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/vpn_service.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/common/proto/ppn_status.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::StatusOr<std::unique_ptr<PpnService>> PpnService::Create(
    desktop::DesktopOAuthInterface* oauth,
    PpnNotificationInterface* ppn_notification,
    krypton::utils::LooperThread* ppn_notification_looper) {
  // Create IPC pipes
  ::privacy::krypton::windows::NamedPipeFactory named_pipe_factory;
  return Create(oauth, ppn_notification, ppn_notification_looper,
                  named_pipe_factory);
}

absl::StatusOr<std::unique_ptr<PpnService>> PpnService::Create(
    desktop::DesktopOAuthInterface* oauth,
    PpnNotificationInterface* ppn_notification,
    krypton::utils::LooperThread* ppn_notification_looper,
    const NamedPipeFactoryInterface& named_pipe_factory) {
  auto app_to_service_pipe =
      named_pipe_factory.CreateNamedPipeInstance(kIpcAppToServicePipeName);
  CHECK_OK(app_to_service_pipe);

  auto service_to_app_pipe =
      named_pipe_factory.CreateNamedPipeInstance(kIpcServiceToAppPipeName);
  CHECK_OK(service_to_app_pipe);

  auto windows_api = std::make_unique<WindowsApi>();
  auto service_to_app_pipe_handler = std::make_unique<IpcPpnService>(
      ppn_notification_looper, ppn_notification, oauth,
      service_to_app_pipe->get(), windows_api.get());

  auto app_to_service_pipe_handler = std::make_unique<IpcPpnService>(
      ppn_notification_looper, ppn_notification, oauth,
      app_to_service_pipe->get(), windows_api.get());

  auto manager = KryptonServiceManager::Create();
  CHECK_OK(manager);

  return std::unique_ptr<PpnService>(new PpnService(
      ppn_notification, ppn_notification_looper,
      *std::move(app_to_service_pipe), *std::move(service_to_app_pipe),
     *std::move(manager), std::move(windows_api),
      std::move(service_to_app_pipe_handler),
      std::move(app_to_service_pipe_handler)));
}

void PpnService::Start(const KryptonConfig& config) {
  {
    absl::MutexLock l(&mutex_);
    krypton_config_ = config;
  }
  LOG(INFO) << "PpnService(C++): PpnService.start method invoked";

  StartWithKryptonService(config);
}

void PpnService::StartWithKryptonService(const KryptonConfig& config) {
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post(
      [ppn_notification] { ppn_notification->PpnStarted(); });
  auto app_to_service_pipe = app_to_service_pipe_.get();
  auto service_to_app_pipe = service_to_app_pipe_.get();
  app_to_service_looper_.Post(
      [app_to_service_pipe] { app_to_service_pipe->WaitForClientToConnect(); });
  service_to_app_looper_.Post(
      [service_to_app_pipe] { service_to_app_pipe->WaitForClientToConnect(); });
  absl::Status status = manager_->StartKryptonService();
  if (!status.ok()) {
    ppn_notification_looper_->Post(
        [ppn_notification, status] { ppn_notification->PpnStopped(status); });
    return;
  }

  auto service_to_app_pipe_handler = service_to_app_pipe_handler_.get();
  service_to_app_looper_.Post([this, service_to_app_pipe_handler] {
    auto pipe_status = service_to_app_pipe_handler->PollOnPipe();
    if (!pipe_status.ok()) {
      LOG(ERROR)
          << "PpnService(C++): Client: Error continuously reading from pipes "
          << pipe_status;
      HandlePipeFailure(pipe_status);
    }
  });

  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::START_KRYPTON);

  *(request.mutable_request()
        ->mutable_start_krypton_request()
        ->mutable_krypton_config()) = config;

  auto response_status = app_to_service_pipe_handler_->CallPipe(request);
  if (!response_status.ok()) {
    LOG(ERROR) << "PpnService(C++): Client: Error making an IPC Request "
               << response_status.status();
    HandlePipeFailure(response_status.status());
    return;
  }
  privacy::krypton::desktop::KryptonControlMessage response = *response_status;

  if (response.response().status().code() != google::rpc::Code::OK) {
    LOG(ERROR) << "PpnService(C++): Error in response:"
               << utils::GetStatusFromRpcStatus(response.response().status());
    ppn_notification_looper_->Post(
        [ppn_notification, status] { ppn_notification->PpnStopped(status); });
    return;
  }
}

void PpnService::Stop(const absl::Status& status) {
  LOG(INFO) << "PpnService(C++): PpnService.stop method invoked";
  StopWithKryptonService(status);
}

void PpnService::StopWithKryptonService(const absl::Status& status) {
  auto app_to_service_pipe = app_to_service_pipe_.get();
  auto service_to_app_pipe = service_to_app_pipe_.get();

  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::STOP_KRYPTON);

  google::rpc::Status rpc_status = utils::GetRpcStatusforStatus(status);
  *(request.mutable_request()
        ->mutable_stop_krypton_request()
        ->mutable_status()) = rpc_status;

  auto response_status = app_to_service_pipe_handler_->CallPipe(request);
  if (!response_status.ok()) {
    LOG(ERROR) << "PpnService(C++): Client: Error connecting to the server: "
               << response_status.status();
    HandlePipeFailure(response_status.status());
    return;
  }

  privacy::krypton::desktop::KryptonControlMessage response = *response_status;
  if (response.response().status().code() != google::rpc::Code::OK) {
    LOG(ERROR) << "PpnService(C++): Error in response:"
               << utils::GetStatusFromRpcStatus(response.response().status());
  }

  app_to_service_pipe_handler_->Stop();
  service_to_app_pipe_handler_->Stop();

  app_to_service_looper_.Post([app_to_service_pipe] {
    app_to_service_pipe->WaitForClientToDisconnect();
  });
  service_to_app_looper_.Post([service_to_app_pipe] {
    service_to_app_pipe->WaitForClientToDisconnect();
  });

  absl::Status stop_status = manager_->StopKryptonService();
  auto ppn_notification = ppn_notification_;

  if (!stop_status.ok()) {
    LOG(ERROR) << "PpnService(C++): Failed to stop Krypton service.";
    return;
  }

  ppn_notification_looper_->Post([ppn_notification, stop_status] {
    ppn_notification->PpnStopped(stop_status);
  });
}

absl::StatusOr<desktop::PpnTelemetry> PpnService::CollectTelemetry() {
  LOG(INFO) << "PpnService(C++): PpnService.CollectTelemetry method invoked";
  auto app_to_service_pipe = app_to_service_pipe_.get();

  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::COLLECT_TELEMETRY);

  auto response_status = app_to_service_pipe_handler_->CallPipe(request);
  if (!response_status.ok()) {
    LOG(ERROR) << "Client: Error connecting to the server: "
               << response_status.status();
    HandlePipeFailure(response_status.status());
    return absl::InternalError("Client: Error connecting to the server");
  }
  privacy::krypton::desktop::KryptonControlMessage response = *response_status;

  if (response.response().status().code() != google::rpc::Code::OK) {
    LOG(ERROR) << "Error in response:"
               << utils::GetStatusFromRpcStatus(response.response().status());
    return absl::InternalError("Client: Error in response from service");
  }
  return response.response().collect_telemetry_response().ppn_telemetry();
}

absl::Status PpnService::SetIpGeoLevel(ppn::IpGeoLevel level) {
  LOG(INFO) << "PpnService(C++): PpnService.SetIpGeoLevel method invoked";
  auto app_to_service_pipe = app_to_service_pipe_.get();

  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::SET_IP_GEO_LEVEL);
  request.mutable_request()->mutable_set_ip_geo_level_request()->set_level(
      level);

  auto response_status = app_to_service_pipe_handler_->CallPipe(request);
  if (!response_status.ok()) {
    LOG(ERROR) << "Client: Error connecting to the server: "
               << response_status.status();
    HandlePipeFailure(response_status.status());
    return absl::InternalError("Client: Error connecting to the server");
  }
  privacy::krypton::desktop::KryptonControlMessage response = *response_status;

  if (response.response().status().code() != google::rpc::Code::OK) {
    LOG(ERROR) << "Error in response:"
               << utils::GetStatusFromRpcStatus(response.response().status());
    return absl::InternalError("Client: Error in response from service");
  }
  return absl::OkStatus();
}

void PpnService::ServiceStopped() {
  LOG(INFO) << "PpnService(C++): Krypton Service stopped. Restarting PPN";
  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post([ppn_notification] {
    ppn_notification->PpnStopped(
        absl::InternalError("Krypton Service stopped"));
  });

  app_to_service_pipe_handler_->Stop();
  service_to_app_pipe_handler_->Stop();

  auto app_to_service_pipe = app_to_service_pipe_.get();
  auto service_to_app_pipe = service_to_app_pipe_.get();

  app_to_service_looper_.Post([app_to_service_pipe] {
    app_to_service_pipe->WaitForClientToDisconnect();
  });
  service_to_app_looper_.Post([service_to_app_pipe] {
    service_to_app_pipe->WaitForClientToDisconnect();
  });

  absl::MutexLock l(&mutex_);
  StartWithKryptonService(krypton_config_);
}

void PpnService::HandlePipeFailure(const absl::Status& status) {
  LOG(INFO) << "In Handle Pipe Failure.";
  // We don't have a good way to identify if pipe failure error we get is
  // because pipes were stopped by the app itself or they failed to connect.
  // We get ERROR_BROKEN_PIPE in both scenarios.
  // Thus, we use stop event on pipes to stop processing ipc calls when we
  // receive a stop message from app and return a CancelledError. Hence, if
  // status is cancelled, it means the pipes have disconnected on app's
  // intention and we don't need to do anything.
  if (absl::IsCancelled(status)) {
    LOG(INFO) << "User initiated cancellation of pipe";
    return;
  }
  auto app_to_service_pipe = app_to_service_pipe_.get();
  auto service_to_app_pipe = service_to_app_pipe_.get();

  app_to_service_pipe_handler_->Stop();
  service_to_app_pipe_handler_->Stop();

  app_to_service_looper_.Post([app_to_service_pipe] {
    app_to_service_pipe->WaitForClientToDisconnect();
  });
  service_to_app_looper_.Post([service_to_app_pipe] {
    service_to_app_pipe->WaitForClientToDisconnect();
  });

  manager_->StopKryptonService();
  absl::Status ipc_failure_status = absl::InternalError("IPC failure");
  ppn::PpnStatusDetails details;
  details.set_detailed_error_code(ppn::PpnStatusDetails::IPC_FAILURE);
  ::privacy::krypton::utils::SetPpnStatusDetails(&ipc_failure_status, details);

  auto ppn_notification = ppn_notification_;
  ppn_notification_looper_->Post([ppn_notification, ipc_failure_status] {
    ppn_notification->PpnStopped(ipc_failure_status);
  });
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
