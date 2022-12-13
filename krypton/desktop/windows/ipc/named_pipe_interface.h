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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_INTERFACE_H_

#include <windows.h>

#include <string>

#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

class NamedPipeInterface {
 public:
  NamedPipeInterface() = default;
  virtual ~NamedPipeInterface() = default;

  /** Wait for client to connect on other side of the pipe. **/
  virtual absl::Status WaitForClientToConnect() = 0;

  /** Wait for client to disconnect on other side of the pipe. **/
  virtual absl::Status WaitForClientToDisconnect() = 0;

  /**
   * Send KryptonControlMessage over the pipe in sync.
   **/
  virtual absl::Status IpcSendSyncMessage(
      const desktop::KryptonControlMessage& message) = 0;

  /**
   * Read KryptonControlMessage from the pipe in sync manner.
   **/
  virtual absl::StatusOr<desktop::KryptonControlMessage>
  IpcReadSyncMessage() = 0;

  /**
   *  Function to read message from pipe as bytes.
   *  Used by IpcReadSyncMessage.
   **/
  virtual absl::StatusOr<std::string> ReadSync(LPOVERLAPPED overlapped) = 0;

  /**
   * Writes a message to the pipe and
   * waits to read a response back in one transaction.
   **/
  virtual absl::StatusOr<desktop::KryptonControlMessage> Call(
      const desktop::KryptonControlMessage& request) = 0;

  virtual HANDLE GetStopPipeEvent() = 0;

  virtual void FlushPipe() = 0;

  virtual absl::Status Initialize() = 0;
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_INTERFACE_H_
