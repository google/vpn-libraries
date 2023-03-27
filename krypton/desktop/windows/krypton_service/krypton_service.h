/*
 * Copyright (C) 2021 Google Inc.
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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_KRYPTON_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_KRYPTON_SERVICE_H_

#include <windows.h>

#include <memory>

#include "base/init_google.h"
#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/http_fetcher.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_krypton_service.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_oauth.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/ppn_notification_receiver.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api.h"
#include "privacy/net/krypton/desktop/windows/logging/file_logger.h"
#include "privacy/net/krypton/desktop/windows/logging/ppn_log_sink.h"
#include "privacy/net/krypton/desktop/windows/network_monitor.h"
#include "privacy/net/krypton/desktop/windows/notification.h"
#include "privacy/net/krypton/desktop/windows/ppn_service_interface.h"
#include "privacy/net/krypton/desktop/windows/timer.h"
#include "privacy/net/krypton/desktop/windows/vpn_service.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

class KryptonService : public PpnServiceInterface,
                       NetworkMonitor::NotificationInterface {
 public:
  KryptonService(NamedPipeFactoryInterface *named_pipe_factory)
      : named_pipe_factory_(named_pipe_factory) {}
  ~KryptonService();

  KryptonService(KryptonService &&) = delete;
  KryptonService(const KryptonService &) = delete;
  KryptonService &operator=(KryptonService &&) = delete;
  KryptonService &operator=(const KryptonService &) = delete;

  // This function should be invoked from the main thread of the service and
  // only returns when the service is stopped. This ensures any reference passed
  // to it would be valid for the service run duration, which is the expected
  // lifetime.
  absl::Status RegisterServiceMain(KryptonService *krypton_service_object);
  // Initialize the app to service pipe handler
  void SetAppToServiceIpcHandler(NamedPipeInterface *pipe);
  // Initialize the app to service pipe handler
  void SetServiceToAppIpcHandler(NamedPipeInterface *pipe);
  // Start krypton
  void Start(const KryptonConfig &config) override;
  // Stop Krypton
  void Stop(const absl::Status &status) override;
  // Collect Telemetry
  absl::StatusOr<desktop::PpnTelemetry> CollectTelemetry() override;
  // Set IP Geo Level
  absl::Status SetIpGeoLevel(ppn::IpGeoLevel level) override;
  // Handles network change notification
  void BestNetworkChanged(std::optional<NetworkInfo> network) override;

 private:
  void InitializeKrypton();
  absl::Status InitializeIpcPipesAndHandlers();

  // Service functions
  static void ServiceMain(DWORD argc, LPTSTR *argv);
  static void ServiceControlHandler(DWORD control);
  void ReportServiceStatus(DWORD current_state, DWORD exit_code,
                           DWORD wait_hint);

  SERVICE_STATUS service_status_{SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_STOPPED,
                                 0,
                                 NO_ERROR,
                                 NO_ERROR,
                                 0,
                                 1000};
  SERVICE_STATUS_HANDLE service_status_handle_;
  HANDLE service_stop_event_;

  std::unique_ptr<privacy::krypton::windows::FileLogger> logger_;
  std::unique_ptr<privacy::krypton::windows::PpnLogSink> log_sink_;

  // This object needs to valid as long as the service is running.
  static KryptonService *krypton_service_;

  NamedPipeFactoryInterface *named_pipe_factory_;
  WindowsApi windows_api_;
  std::unique_ptr<NamedPipeInterface> app_to_service_pipe_;
  std::unique_ptr<NamedPipeInterface> service_to_app_pipe_;
  std::unique_ptr<IpcKryptonService> app_to_service_pipe_ipc_handler_;
  std::unique_ptr<IpcKryptonService> service_to_app_pipe_ipc_handler_;
  krypton::utils::LooperThread ipc_looper_{"IPC Looper"};

  HttpFetcher http_fetcher_;
  std::unique_ptr<KryptonClock> clock_;
  std::unique_ptr<privacy::krypton::windows::IpcOauth> oauth_;
  VpnService vpn_service_;
  std::unique_ptr<PpnTelemetryManager> ppn_telemetry_manager_;
  std::unique_ptr<TimerManager> timer_manager_;
  std::unique_ptr<PpnNotificationReceiver> ppn_notification_;
  krypton::utils::LooperThread ppn_notification_looper_{
      "PpnNotification Looper"};
  std::unique_ptr<Notification> notification_;

  std::unique_ptr<Krypton> krypton_;
  krypton::utils::LooperThread xenon_looper_{"Xenon Looper"};
  std::unique_ptr<NetworkMonitor> xenon_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_KRYPTON_SERVICE_H_
