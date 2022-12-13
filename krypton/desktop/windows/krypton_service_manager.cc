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

#include "privacy/net/krypton/desktop/windows/krypton_service_manager.h"

#include <strsafe.h>
#include <tchar.h>
#include <windows.h>
#include <winsvc.h>

#include <functional>
#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/constants.h"
#include "privacy/net/krypton/desktop/windows/service_monitor_interface.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/desktop/windows/utils/file_utils.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

VOID CALLBACK NotifyCallback(PVOID parameter) {
  PSERVICE_NOTIFY service_notify = (PSERVICE_NOTIFY)parameter;
  HANDLE notify_event = (HANDLE)service_notify->pContext;

  if (service_notify->ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
    LOG(INFO) << "Service entered RUNNING state";
  } else if (service_notify->ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
    LOG(INFO) << "Service entered STOPPED state";
  } else {
    LOG(INFO) << "Service entered state: "
              << service_notify->ServiceStatus.dwCurrentState;
  }
  // Signal that the state has changed
  SetEvent(notify_event);
}

absl::StatusOr<std::unique_ptr<KryptonServiceManager>>
KryptonServiceManager::Create() {
  // Get a handle to the SCM database.
  SC_HANDLE sc_manager = OpenSCManager(NULL,  // local computer
                                       NULL,  // servicesActive database
                                       SC_MANAGER_CONNECT);

  if (sc_manager == nullptr) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed to create a svc manager handle with error", GetLastError());
  }

  LOG(INFO) << "OpenSCManager successful";

  // Get a handle to the service.
  SC_HANDLE sc_service =
      OpenService(sc_manager,       // SCM database
                  kKryptonSvcName,  // name of service
                  SERVICE_START | SERVICE_STOP | GENERIC_READ);  // access

  if (sc_service == nullptr) {
    CloseServiceHandle(sc_manager);
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed to create a service handle with error", GetLastError());
  }
  LOG(INFO) << "OpenService successful";

  absl::StatusOr<HANDLE> notify_event_status = utils::CreateManualResetEvent();
  if (!notify_event_status.ok()) {
    LOG(ERROR) << notify_event_status.status();
    return absl::InternalError("Failed to create Event");
  }
  HANDLE notify_event = *notify_event_status;
  if (notify_event == NULL) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Creation of event failed", GetLastError());
  }

  absl::StatusOr<HANDLE> stop_monitoring_event_status =
      utils::CreateManualResetEvent();
  if (!stop_monitoring_event_status.ok()) {
    LOG(ERROR) << stop_monitoring_event_status.status();
    return absl::InternalError("Failed to create service monitoring Event");
  }
  HANDLE stop_monitoring_event = *stop_monitoring_event_status;
  if (stop_monitoring_event == NULL) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Creation of service monitoring event failed", GetLastError());
  }

  absl::StatusOr<HANDLE> monitoring_notify_event_status =
      utils::CreateManualResetEvent();
  if (!monitoring_notify_event_status.ok()) {
    LOG(ERROR) << monitoring_notify_event_status.status();
    return absl::InternalError("Failed to create service monitoring Event");
  }
  HANDLE monitoring_notify_event = *monitoring_notify_event_status;
  if (monitoring_notify_event == NULL) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Creation of service monitoring event failed", GetLastError());
  }

  return std::unique_ptr<KryptonServiceManager>(new KryptonServiceManager(
      sc_manager, sc_service, notify_event, stop_monitoring_event,
      monitoring_notify_event));
}

void KryptonServiceManager::RegisterServiceMonitor(
    ServiceMonitorInterface *service_monitor) {
  service_monitor_ = service_monitor;
}

KryptonServiceManager::~KryptonServiceManager() {
  CloseServiceHandle(sc_service_);
  CloseServiceHandle(sc_manager_);
  CloseHandle(notify_event_);
  CloseHandle(monitoring_notify_event_);
  CloseHandle(stop_monitoring_event_);
}

absl::Status KryptonServiceManager::StartKryptonService() {
  if (sc_service_ == NULL) {
    return absl::InternalError("Service is not open. Service handle is NULL.");
  }
  SERVICE_STATUS_PROCESS service_status;
  DWORD bytes_needed;

  // Check the status in case the service is not stopped.
  if (!QueryServiceStatusEx(
          sc_service_,                     // handle to service
          SC_STATUS_PROCESS_INFO,          // information level
          (LPBYTE)&service_status,         // address of structure
          sizeof(SERVICE_STATUS_PROCESS),  // size of structure
          &bytes_needed))                  // size needed if buffer is too small
  {
    return utils::GetStatusForError("QueryServiceStatusEx failed: ",
                                    GetLastError());
  }

  LOG(INFO) << "Current service status: " << service_status.dwCurrentState;

  // Check if the service is already running. Stop the service and restart.
  if (service_status.dwCurrentState != SERVICE_STOPPED &&
      service_status.dwCurrentState != SERVICE_STOP_PENDING) {
    LOG(INFO) << "Stopping the service as it is already running";
    auto stop_status = StopKryptonService();
    if (!stop_status.ok()) {
      return stop_status;
    }
  }

  if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
    absl::Status notification_status =
        WaitForStateChangeNotification(SERVICE_NOTIFY_STOPPED);
    if (!notification_status.ok()) {
      return notification_status;
    }
  }

  // Attempt to start the service.
  auto local_app_dir = utils::CreateLocalAppDataPath();
  CHECK_OK(local_app_dir);

  auto local_app_dir_path = local_app_dir->c_str();
  if (StartServiceW(sc_service_,                // handle to service
                    1,                          // number of arguments
                    &local_app_dir_path) == 0)  // local app directory location
  {
    return utils::GetStatusForError("StartService failed: ", GetLastError());
  }
  LOG(INFO) << "Service start pending...";

  absl::Status notification_status = WaitForStateChangeNotification(
      SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED);
  if (!notification_status.ok()) {
    return notification_status;
  }

  if (!QueryServiceStatusEx(
          sc_service_,                     // handle to service
          SC_STATUS_PROCESS_INFO,          // information level
          (LPBYTE)&service_status,         // address of structure
          sizeof(SERVICE_STATUS_PROCESS),  // size of structure
          &bytes_needed))                  // size needed if buffer is too small
  {
    return utils::GetStatusForError("QueryServiceStatusEx [2] failed: ",
                                    GetLastError());
  }

  // Determine whether the service is running.
  if (service_status.dwCurrentState != SERVICE_RUNNING) {
    LOG(ERROR) << "Service not started.";
    LOG(ERROR) << "  Current State: " << service_status.dwCurrentState;
    LOG(ERROR) << "  Exit Code: " << service_status.dwWin32ExitCode;
    LOG(ERROR) << "  Check Point: " << service_status.dwCheckPoint;
    LOG(ERROR) << "  Wait Hint: " << service_status.dwWaitHint;
    return absl::InternalError("Service not started.");
  }
  LOG(INFO) << "Service started successfully.";
  absl::MutexLock l(&mutex_);
  if (!monitoring_) {
    StartMonitoringKryptonService();
    monitoring_ = true;
  }
  return absl::OkStatus();
}

absl::Status KryptonServiceManager::StopKryptonService() {
  {
    absl::MutexLock l(&mutex_);
    if (monitoring_) {
      StopMonitoringKryptonService();
      monitoring_ = false;
    }
  }
  if (sc_service_ == NULL) {
    return absl::InternalError("Service is not open. Service handle is NULL.");
  }

  // Make sure the service is not already stopped.
  SERVICE_STATUS_PROCESS service_status;
  DWORD bytes_needed;
  if (!QueryServiceStatusEx(sc_service_, SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&service_status,
                            sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)) {
    return utils::GetStatusForError("QueryServiceStatusEx failed: ",
                                    GetLastError());
  }

  if (service_status.dwCurrentState == SERVICE_STOPPED) {
    LOG(INFO) << "Service is already stopped.";
    return absl::OkStatus();
  }

  if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
    absl::Status notification_status =
        WaitForStateChangeNotification(SERVICE_NOTIFY_STOPPED);
    return notification_status;
  }

  // Send a stop code to the service.
  if (!ControlService(sc_service_, SERVICE_CONTROL_STOP,
                      (LPSERVICE_STATUS)&service_status)) {
    return utils::GetStatusForError("ControlService failed: ", GetLastError());
  }

  absl::Status notification_status =
      WaitForStateChangeNotification(SERVICE_NOTIFY_STOPPED);
  if (!notification_status.ok()) {
    return notification_status;
  }
  LOG(INFO) << "Service stopped successfully.";
  return absl::OkStatus();
}

absl::Status KryptonServiceManager::WaitForStateChangeNotification(
    DWORD notification_state) {
  ResetEvent(notify_event_);
  // Initialize callback context
  HANDLE notify_context = (HANDLE)notify_event_;

  // Initialize notification struct
  SERVICE_NOTIFY service_notify = {};
  service_notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
  service_notify.pfnNotifyCallback = (PFN_SC_NOTIFY_CALLBACK)NotifyCallback;
  service_notify.pContext = notify_context;

  DWORD notify_status = NotifyServiceStatusChange(
      sc_service_, notification_state, &service_notify);

  if (notify_status != ERROR_SUCCESS) {
    return utils::GetStatusForError("NotifyServiceStatusChange failed: ",
                                    GetLastError());
  }

  notify_status = WaitForSingleObjectEx(notify_event_, INFINITE, TRUE);
  return absl::OkStatus();
}

void KryptonServiceManager::StartMonitoringKryptonService() {
  ResetEvent(stop_monitoring_event_);
  service_monitoring_looper_ = std::make_unique<krypton::utils::LooperThread>(
      "Krypton Service monitoring Looper");
  service_monitoring_looper_->Post([this]() { MonitorKryptonService(); });
  LOG(INFO) << "Started monitoring Krypton Service";
}

void KryptonServiceManager::StopMonitoringKryptonService() {
  SetEvent(stop_monitoring_event_);
  service_monitoring_looper_->Stop();
  service_monitoring_looper_->Join();
  LOG(INFO) << "Stopped monitoring Krypton Service";
}

void KryptonServiceManager::MonitorKryptonService() {
  while (true) {
    LOG(INFO) << "Monitoring Krypton Service...";
    ResetEvent(monitoring_notify_event_);
    // Initialize callback context
    HANDLE notify_context = (HANDLE)monitoring_notify_event_;

    // Initialize notification struct
    SERVICE_NOTIFY service_notify = {};
    service_notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    service_notify.pfnNotifyCallback = (PFN_SC_NOTIFY_CALLBACK)NotifyCallback;
    service_notify.pContext = notify_context;

    DWORD notify_status = NotifyServiceStatusChange(
        sc_service_, SERVICE_NOTIFY_STOPPED, &service_notify);

    if (notify_status != ERROR_SUCCESS) {
      LOG(ERROR) << "NotifyServiceStatusChange failed: " << GetLastError();
    }
    HANDLE handles[2] = {stop_monitoring_event_, monitoring_notify_event_};
    LOG(INFO) << "Waiting for any action in service monitor... ";

    DWORD wait_result;
    do {
      wait_result = WaitForMultipleObjectsEx(2, handles, FALSE, INFINITE, TRUE);
    } while (wait_result == WAIT_IO_COMPLETION);

    switch (wait_result) {
      // First event: Stop monitoring event.
      case WAIT_OBJECT_0:
        LOG(INFO) << "Ended monitoring due to Ppn stop";
        return;
      // Second event: Service state changed to stop.
      case WAIT_OBJECT_0 + 1:
        LOG(INFO) << "Service state change captured";
        service_monitor_->ServiceStopped();
        break;
      // Unknown event. An error occurred in the wait function.
      default:
        LOG(ERROR) << "WaitForMultipleObjectsEx returned wait_result: "
                   << wait_result;
    }
  }
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
