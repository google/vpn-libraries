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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_PPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_PPN_SERVICE_H_

#include "privacy/net/krypton/desktop/desktop_oauth_interface.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/ipc_service.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api_interface.h"
#include "privacy/net/krypton/desktop/windows/ppn_notification_interface.h"
#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {
namespace windows {

/**
 * Handles the Ipc Calls made from the ppn service.
 **/
class IpcPpnService : public IpcService {
 public:
  explicit IpcPpnService(krypton::utils::LooperThread* ppn_notification_looper,
                         PpnNotificationInterface* ppn_notification,
                         desktop::DesktopOAuthInterface* oauth,
                         NamedPipeInterface* named_pipe_interface,
                         WindowsApiInterface* windows_api)
      : IpcService(named_pipe_interface, windows_api),
        ppn_notification_looper_(ppn_notification_looper),
        ppn_notification_(ppn_notification),
        oauth_(oauth) {}
  ~IpcPpnService() override;

  // Deleting copy and move constructors.
  IpcPpnService(const IpcPpnService& arg) = delete;
  IpcPpnService& operator=(const IpcPpnService& rhs) = delete;
  IpcPpnService(IpcPpnService&& arg) = delete;
  IpcPpnService& operator=(IpcPpnService&& rhs) = delete;

 private:
  /**
   * Process the message passed in and performs needed action on Krypton via
   * PpnServiceInterface.
   **/
  desktop::KryptonControlMessage ProcessKryptonControlMessage(
      desktop::KryptonControlMessage message) override;
  /**
   * Validates Request received from the pipe.
   **/
  absl::Status ValidateRequest(
      krypton::desktop::KryptonControlMessage message) override;
  /**
   * Enqueue Notification in the request for processing and respond back.
   **/
  void HandleNotification(desktop::KryptonControlRequest request,
                          google::rpc::Status* status);

  // Notification Looper for enqueuing notification updates from the service.
  krypton::utils::LooperThread* ppn_notification_looper_;
  // Notification interface to trigger different notification updates.
  PpnNotificationInterface* ppn_notification_;
  // Oauth Interface to fetch ouath token when asked by service.
  desktop::DesktopOAuthInterface* oauth_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_PPN_SERVICE_H_
