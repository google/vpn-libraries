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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_KRYPTON_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_KRYPTON_SERVICE_H_

#include <utility>

#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api.h"
#include "privacy/net/krypton/desktop/windows/ppn_service_interface.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

/**
 * Class to control IPC Communication with Krypton.
 **/
class IpcKryptonService {
 public:
  explicit IpcKryptonService(NamedPipeInterface* named_pipe_interface,
                             WindowsApiInterface* windows_api)
      : named_pipe_interface_(ABSL_DIE_IF_NULL(named_pipe_interface)),
        windows_api_(windows_api) {}
  ~IpcKryptonService() = default;

  /**
   * Continuously calls ReadAndWriteToPipe (i.e reads data from the pipe,
   * processes it and writes the response back to the pipe), until close event
   *on pipe is not signaled.
   **/
  absl::Status PollOnPipe(PpnServiceInterface* service);
  /**
   * Waits for data, reads it, processes it and writes back.
   **/
  absl::Status ReadAndWriteToPipe(PpnServiceInterface* service);
  /**
   * Calls Pipe with request and waits for the response back.
   **/
  absl::StatusOr<desktop::KryptonControlMessage> CallPipe(
      desktop::KryptonControlMessage request);

  /**
   * Process the message passed in and performs needed action on Krypton via
   * PpnServiceInterface.
   **/
  desktop::KryptonControlMessage ProcessAppToServiceMessage(
      PpnServiceInterface* service, desktop::KryptonControlMessage message);

  void Stop();

 private:
  /**
   * Validates Request received from the pipe.
   **/
  absl::Status ValidateRequest(krypton::desktop::KryptonControlMessage message);

  NamedPipeInterface* named_pipe_interface_;
  WindowsApiInterface* windows_api_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_KRYPTON_SERVICE_H_
