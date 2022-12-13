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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_H_

#include <string>
#include <vector>

#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

class NamedPipe : public NamedPipeInterface {
 public:
  NamedPipe() : pipe_(nullptr) {}
  explicit NamedPipe(HANDLE pipe) : pipe_(pipe) {}
  ~NamedPipe() override;

  NamedPipe(const NamedPipe& arg) = delete;
  NamedPipe& operator=(const NamedPipe& rhs) = delete;
  NamedPipe(NamedPipe&& arg) = delete;
  NamedPipe& operator=(NamedPipe&& rhs) = delete;

  /** Wait for client to connect on other side of the pipe. **/
  absl::Status WaitForClientToConnect() override;

  /** Wait for client to disconnect on other side of the pipe. **/
  absl::Status WaitForClientToDisconnect() override;

  /**
   * Send KryptonControlMessage over the pipe in sync.
   **/
  absl::Status IpcSendSyncMessage(
      const desktop::KryptonControlMessage& message) override;

  /**
   * Read KryptonControlMessage from the pipe in sync manner.
   **/
  absl::StatusOr<desktop::KryptonControlMessage> IpcReadSyncMessage() override;

  /**
   * Writes a message to the pipe and
   * waits to read a response back in one transaction.
   * Mutex is added to allow only one call at one time in a pipe instance.
   **/
  absl::StatusOr<desktop::KryptonControlMessage> Call(
      const desktop::KryptonControlMessage& request)
      ABSL_LOCKS_EXCLUDED(call_state_mutex_) override;

  /**
   *  Initializes all members of named pipe instance.
   **/
  absl::Status Initialize() ABSL_LOCKS_EXCLUDED(call_state_mutex_) override;

  HANDLE GetStopPipeEvent() ABSL_LOCKS_EXCLUDED(call_state_mutex_) override;

  void FlushPipe() override;

 private:
  HANDLE pipe_;
  // Event used to signal terminate any new pipe operations.
  HANDLE stop_pipe_event_;
  // Overlapped structure for all read operations. Contains the event which is
  // signaled when a read operation completes.
  OVERLAPPED read_state_;
  // Overlapped structure for all write operations. Contains the event which is
  // signaled when a write operation completes.
  OVERLAPPED write_state_;
  // Overlapped structure for connect to pipe operations. Contains the event
  // which is signaled when a successful connection to pipe is setup.
  OVERLAPPED connection_state_;
  // Overlapped structure for all call operations. Contains the event which is
  // signaled when a call operation completes.
  OVERLAPPED call_state_ ABSL_GUARDED_BY(call_state_mutex_);

  absl::Mutex call_state_mutex_;

  absl::Status WaitOnHandles(HANDLE close_pipe_handle,
                             HANDLE overlapped_handle);

  void Close();

  /**
   * Function to read message from pipe as bytes by passing a valid overlapped
   * structure. Used by IpcReadSyncMessage and Call functions.
   **/
  absl::StatusOr<std::string> ReadSync(LPOVERLAPPED overlapped) override;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_H_
