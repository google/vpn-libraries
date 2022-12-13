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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_MANAGER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_MANAGER_H_

#include <windows.h>

#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/service_monitor_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

// Holds Krypton Instance and manages PPN.
class KryptonServiceManager {
 public:
  ~KryptonServiceManager();

  // Deleting copy and move constructors
  KryptonServiceManager(KryptonServiceManager &&) = delete;
  KryptonServiceManager(const KryptonServiceManager &) = delete;
  KryptonServiceManager &operator=(KryptonServiceManager &&) = delete;
  KryptonServiceManager &operator=(const KryptonServiceManager &) = delete;

  static absl::StatusOr<std::unique_ptr<KryptonServiceManager>> Create();
  void RegisterServiceMonitor(ServiceMonitorInterface *service_monitor);

  absl::Status StartKryptonService() ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status StopKryptonService() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  ServiceMonitorInterface *service_monitor_;
  SC_HANDLE sc_manager_;
  SC_HANDLE sc_service_;
  // Event to notify state change in service due to start/stop
  HANDLE notify_event_;
  // Event to notify when to stop monitoring
  HANDLE stop_monitoring_event_;
  // Event to notify state change in service while monitoring
  HANDLE monitoring_notify_event_;
  absl::Mutex mutex_;
  bool monitoring_ ABSL_GUARDED_BY(mutex_) = false;
  std::unique_ptr<krypton::utils::LooperThread> service_monitoring_looper_;

  KryptonServiceManager(SC_HANDLE sc_manager, SC_HANDLE sc_service,
                        HANDLE notify_event, HANDLE stop_monitoring_event,
                        HANDLE monitoring_notify_event)
      : sc_manager_(sc_manager),
        sc_service_(sc_service),
        notify_event_(notify_event),
        stop_monitoring_event_(stop_monitoring_event),
        monitoring_notify_event_(monitoring_notify_event) {}

  absl::Status WaitForStateChangeNotification(DWORD notification_state);

  // Start monitoring Krypton Service
  void StartMonitoringKryptonService();
  // Stop monitoring Krypton Service
  void StopMonitoringKryptonService();
  // Continuously monitor Krypton Service till stop is called
  void MonitorKryptonService();
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_MANAGER_H_
