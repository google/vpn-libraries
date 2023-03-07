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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_SERVICE_H_

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api_interface.h"

namespace privacy {
namespace krypton {
namespace windows {

class IpcService {
 public:
  explicit IpcService(NamedPipeInterface* named_pipe_interface,
                      WindowsApiInterface* windows_api)
      : named_pipe_interface_(named_pipe_interface),
        windows_api_(windows_api) {}
  virtual ~IpcService() = 0;

  // Deleting copy and move constructors.
  IpcService(const IpcService&) = delete;
  IpcService& operator=(const IpcService&) = delete;
  IpcService(IpcService&&) = delete;
  IpcService& operator=(IpcService&&) = delete;

  /**
   * Continuously calls ReadAndWriteToPipe (i.e reads data from the pipe,
   * processes it and writes the response back to the pipe), until close event
   * on pipe is not signaled.
   **/
  absl::Status PollOnPipe();
  /**
   * Calls Pipe with request and waits for the response back.
   **/
  absl::StatusOr<desktop::KryptonControlMessage> CallPipe(
      desktop::KryptonControlMessage request);
  /**
   * Triggers stop event for IPC pipe handled here.
   **/
  void Stop();
  /**
   * Waits for data, reads it, processes it and writes back.
   **/
  absl::Status ReadAndWriteToPipe();

 private:
  /**
   * Process the message passed in and performs needed action on Krypton via
   * PpnServiceInterface.
   **/
  virtual desktop::KryptonControlMessage ProcessKryptonControlMessage(
      desktop::KryptonControlMessage message) = 0;
  /**
   * Validates Request received from the pipe.
   **/
  virtual absl::Status ValidateRequest(
      krypton::desktop::KryptonControlMessage message) = 0;

  NamedPipeInterface* named_pipe_interface_;
  WindowsApiInterface* windows_api_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_SERVICE_H_
