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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_H_

#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/desktop/desktop_oauth_interface.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory_interface.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/ipc_ppn_service.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api.h"
#include "privacy/net/krypton/desktop/windows/krypton_service_manager.h"
#include "privacy/net/krypton/desktop/windows/ppn_notification_interface.h"
#include "privacy/net/krypton/desktop/windows/ppn_service_interface.h"
#include "privacy/net/krypton/desktop/windows/service_monitor_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {

// Holds Krypton Instance and manages PPN.
class PpnService : public PpnServiceInterface, ServiceMonitorInterface {
 public:
  static absl::StatusOr<std::unique_ptr<PpnService>> Create(
      desktop::DesktopOAuthInterface* oauth,
      PpnNotificationInterface* ppn_notification,
      krypton::utils::LooperThread* ppn_notification_looper);

  static absl::StatusOr<std::unique_ptr<PpnService>> Create(
      desktop::DesktopOAuthInterface* oauth,
      PpnNotificationInterface* ppn_notification,
      krypton::utils::LooperThread* ppn_notification_looper,
      const NamedPipeFactoryInterface& named_pipe_factory);

  // Deleting copy and move constructors
  PpnService(PpnService&&) = delete;
  PpnService(const PpnService&) = delete;
  PpnService& operator=(PpnService&&) = delete;
  PpnService& operator=(const PpnService&) = delete;

  ~PpnService() override = default;

  // Starts PPN
  void Start(const KryptonConfig& config) ABSL_LOCKS_EXCLUDED(mutex_) override;

  // Stops PPN
  void Stop(const absl::Status& status) override;

  // Collects Telemetry from Krypton
  absl::StatusOr<desktop::PpnTelemetry> CollectTelemetry() override;

  // Sets the geographical granularity of IP allocation.
  absl::Status SetIpGeoLevel(ppn::IpGeoLevel level) override;

  void ServiceStopped() ABSL_LOCKS_EXCLUDED(mutex_) override;

 private:
  PpnNotificationInterface* ppn_notification_;
  krypton::utils::LooperThread* ppn_notification_looper_;

  // IPC pipes for communication with Krypton Service.
  std::unique_ptr<privacy::krypton::windows::NamedPipeInterface>
      app_to_service_pipe_;
  std::unique_ptr<privacy::krypton::windows::NamedPipeInterface>
      service_to_app_pipe_;

  privacy::krypton::utils::LooperThread app_to_service_looper_{
      "App to Service IPC Looper"};
  privacy::krypton::utils::LooperThread service_to_app_looper_{
      "Service to App IPC Looper"};
  std::unique_ptr<KryptonServiceManager> manager_;
  std::unique_ptr<WindowsApi> windows_api_;
  std::unique_ptr<IpcPpnService> service_to_app_pipe_handler_;
  std::unique_ptr<IpcPpnService> app_to_service_pipe_handler_;
  absl::Mutex mutex_;
  KryptonConfig krypton_config_ ABSL_GUARDED_BY(mutex_);

  PpnService(PpnNotificationInterface* ppn_notification,
             krypton::utils::LooperThread* ppn_notification_looper,
             std::unique_ptr<privacy::krypton::windows::NamedPipeInterface>
                 app_to_service_pipe,
             std::unique_ptr<privacy::krypton::windows::NamedPipeInterface>
                 service_to_app_pipe,
             std::unique_ptr<KryptonServiceManager> manager,
             std::unique_ptr<WindowsApi> windows_api,
             std::unique_ptr<IpcPpnService> service_to_app_pipe_handler,
             std::unique_ptr<IpcPpnService> app_to_service_pipe_handler)
      : ppn_notification_(ppn_notification),
        ppn_notification_looper_(ppn_notification_looper),
        app_to_service_pipe_(std::move(app_to_service_pipe)),
        service_to_app_pipe_(std::move(service_to_app_pipe)),
        manager_(std::move(manager)),
        windows_api_(std::move(windows_api)),
        service_to_app_pipe_handler_(std::move(service_to_app_pipe_handler)),
        app_to_service_pipe_handler_(std::move(app_to_service_pipe_handler)) {
    manager_->RegisterServiceMonitor(this);
  }

  void StartWithKryptonService(const KryptonConfig& config);
  void StopWithKryptonService(const absl::Status& status);
  void HandlePipeFailure(const absl::Status& status);
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_H_
