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

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe.h"

#include <namedpipeapi.h>
#include <windows.h>

#include <string>
#include <vector>

#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace windows {

static constexpr const auto kPipeBufferSize = 4096;
static constexpr const auto kPipeWaitTime = 1000;

NamedPipe::~NamedPipe() { Close(); }

absl::Status NamedPipe::WaitForClientToConnect() {
  // Non zero value indicates error.
  // https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o
  ResetEvent(stop_pipe_event_);
  BOOL connected = ConnectNamedPipe(pipe_, &connection_state_);
  if (connected != 0) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed waiting for client to connect with error: ", GetLastError());
  }
  DWORD last_error = GetLastError();
  switch (last_error) {
    case ERROR_IO_PENDING:
      LOG(INFO) << "IO is Pending";
      break;
    // https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe#return-value
    case ERROR_PIPE_CONNECTED:
      LOG(INFO) << "Pipe connected";
      SetEvent(connection_state_.hEvent);
      break;
    default:
      return privacy::krypton::windows::utils::GetStatusForError(
          "Failed waiting for client to connect with error", last_error);
  }
  PPN_RETURN_IF_ERROR(
      WaitOnHandles(stop_pipe_event_, connection_state_.hEvent));
  DWORD bytes;
  if (!GetOverlappedResult(pipe_, &connection_state_, &bytes, false)) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed waiting for client to connect with error", GetLastError());
  }
  return absl::OkStatus();
}

absl::Status NamedPipe::WaitForClientToDisconnect() {
  // Wait until all the messages are read
  FlushFileBuffers(pipe_);
  // If the function fails, the return value is zero.
  BOOL status = DisconnectNamedPipe(pipe_);
  if (status == 0) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed waiting for client to disconnect with error: ", GetLastError());
  }
  return absl::OkStatus();
}

absl::Status NamedPipe::IpcSendSyncMessage(
    const desktop::KryptonControlMessage& message) {
  std::string buffer;
  message.SerializeToString(&buffer);
  DWORD bytes_written = 0;
  BOOL write_to_pipe = WriteFile(pipe_, buffer.data(), buffer.size(),
                                 &bytes_written, &write_state_);
  if (write_to_pipe && bytes_written == buffer.size()) {
    return absl::OkStatus();
  } else if (write_to_pipe) {
    return absl::InternalError(absl::Substitute(
        "Write to pipe failed after writing $0 for message of size $1",
        bytes_written, buffer.size()));
  }

  DWORD last_error = GetLastError();
  switch (last_error) {
    case ERROR_IO_PENDING: {
      (void)WaitOnHandles(stop_pipe_event_, write_state_.hEvent);
      if (!GetOverlappedResult(pipe_, &write_state_, &bytes_written, false)) {
        return privacy::krypton::windows::utils::GetStatusForError(
            "Failed waiting for client to connect with error", GetLastError());
      }
      return absl::OkStatus();
    }
    default:
      return privacy::krypton::windows::utils::GetStatusForError(
          "Failed waiting for client to connect with error", last_error);
  }
  return privacy::krypton::windows::utils::GetStatusForError(
      "Failed waiting for client to connect with error", GetLastError());
}

absl::StatusOr<desktop::KryptonControlMessage> NamedPipe::IpcReadSyncMessage() {
  PPN_ASSIGN_OR_RETURN(std::string message, ReadSync(&read_state_));
  desktop::KryptonControlMessage krypton_control_message;
  krypton_control_message.ParseFromArray(message.data(),
                                         static_cast<int>(message.size()));
  return krypton_control_message;
}

absl::StatusOr<std::string> NamedPipe::ReadSync(LPOVERLAPPED overlapped) {
  bool success = false;
  std::string message;
  DWORD last_error;
  char buffer[kPipeBufferSize] = {0};
  DWORD bytes_read;
  success = ReadFile(pipe_, &buffer, kPipeBufferSize, &bytes_read, overlapped);
  if (success && bytes_read != 0) {
    message.append(buffer, bytes_read);
    LOG(INFO) << "Read " << bytes_read << " bytes from the pipe ";
    return message;
  }
  last_error = GetLastError();
  if (!success && last_error != ERROR_IO_PENDING) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Read from Sync pipe failed", last_error);
  }
  PPN_RETURN_IF_ERROR(WaitOnHandles(stop_pipe_event_, overlapped->hEvent));
  while (true) {
    DWORD bytes_transferred;
    BOOL overlapped_result =
        GetOverlappedResult(pipe_, overlapped, &bytes_transferred, FALSE);
    if (!overlapped_result) {
      last_error = GetLastError();
      if (last_error == ERROR_MORE_DATA) {
        message.append(buffer, bytes_transferred);
        success =
            ReadFile(pipe_, &buffer, kPipeBufferSize, &bytes_read, overlapped);
        if (success && bytes_read != 0) {
          message.append(buffer, bytes_read);
          return message;
        }
        if (!success && last_error != ERROR_IO_PENDING) {
          return privacy::krypton::windows::utils::GetStatusForError(
              absl::Substitute(
                  "Read from Sync pipe failed after reading $0 bytes",
                  message.size()),
              last_error);
        }
        (void)WaitOnHandles(stop_pipe_event_, overlapped->hEvent);
        continue;
      } else {
        return privacy::krypton::windows::utils::GetStatusForError(
            "Failed waiting for client to connect with error", last_error);
      }
    }
    message.append(buffer, bytes_transferred);
    break;
  }
  LOG(INFO) << "Read " << message.size() << " bytes from the pipe";
  return message;
}

absl::StatusOr<desktop::KryptonControlMessage> NamedPipe::Call(
    const desktop::KryptonControlMessage& request) {
  absl::MutexLock l(&call_state_mutex_);
  desktop::KryptonControlMessage response;
  DWORD bytes_read;
  std::string input_buffer;
  request.SerializeToString(&input_buffer);
  char output_buffer[kPipeBufferSize];
  std::string final_output;
  // TransactNamedPipe reads for the buffer size and returns ERROR_MORE_DATA
  // in case the message is larger than buffer size. Thus, we follow this call
  // with ReadSyncFromPipe call which appends rest of the data in a loop to
  // final_output buffer.
  BOOL result = TransactNamedPipe(pipe_, input_buffer.data(),
                                  input_buffer.size(), output_buffer,
                                  kPipeBufferSize, &bytes_read, &call_state_);
  if (result && bytes_read != 0) {
    final_output.append(output_buffer, bytes_read);
    response.ParseFromArray(final_output.data(), final_output.size());
    return response;
  } else if (result) {
    return absl::InternalError(
        "No bytes read received from Call on Pipe even after success.");
  }
  DWORD last_error = GetLastError();
  if (!result && last_error != ERROR_IO_PENDING) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Read from Sync pipe failed", last_error);
  }
  PPN_RETURN_IF_ERROR(WaitOnHandles(stop_pipe_event_, call_state_.hEvent));
  while (true) {
    DWORD bytes_transferred;
    BOOL overlapped_result =
        GetOverlappedResult(pipe_, &call_state_, &bytes_transferred, FALSE);
    if (!overlapped_result) {
      last_error = GetLastError();
      if (last_error == ERROR_MORE_DATA) {
        final_output.append(output_buffer, bytes_transferred);
        PPN_ASSIGN_OR_RETURN(std::string buffer, ReadSync(&call_state_));
        final_output.append(buffer);
        break;
      } else {
        return privacy::krypton::windows::utils::GetStatusForError(
            "Failed waiting for client to connect with error", last_error);
      }
    } else {
      final_output.append(output_buffer, bytes_transferred);
      break;
    }
  }
  LOG(INFO) << "Bytes read by client: " << final_output.size();
  response.ParseFromArray(final_output.data(), final_output.size());
  return response;
}

absl::Status NamedPipe::WaitOnHandles(HANDLE stop_pipe_handle,
                                      HANDLE overlapped_handle) {
  HANDLE handles[2] = {stop_pipe_handle, overlapped_handle};
  auto result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
  LOG(INFO) << "Waiting on Handles";
  switch (result) {
    case WAIT_OBJECT_0 + 0: {
      // The close pipe handle is signaled.
      return absl::CancelledError("Stop on pipe is called");
    }
    case WAIT_OBJECT_0 + 1: {
      // The overlapped handle is signaled which means pending overlapped
      // operation is complete. Return.
      return absl::OkStatus();
    }
    default: {
      return absl::InternalError("WaitForMultipleObjects failed");
    }
  }
}

HANDLE NamedPipe::GetStopPipeEvent() { return stop_pipe_event_; }

absl::Status NamedPipe::Initialize() {
  OVERLAPPED overlapped_read;
  overlapped_read.Offset = 0;
  overlapped_read.OffsetHigh = 0;
  PPN_ASSIGN_OR_RETURN(overlapped_read.hEvent, utils::CreateManualResetEvent());
  read_state_ = overlapped_read;

  OVERLAPPED overlapped_write;
  overlapped_write.Offset = 0;
  overlapped_write.OffsetHigh = 0;
  PPN_ASSIGN_OR_RETURN(overlapped_write.hEvent,
                       utils::CreateManualResetEvent());
  write_state_ = overlapped_write;

  OVERLAPPED overlapped_connect;
  overlapped_connect.Offset = 0;
  overlapped_connect.OffsetHigh = 0;
  PPN_ASSIGN_OR_RETURN(overlapped_connect.hEvent,
                       utils::CreateManualResetEvent());
  connection_state_ = overlapped_connect;

  OVERLAPPED overlapped_call;
  overlapped_call.Offset = 0;
  overlapped_call.OffsetHigh = 0;
  PPN_ASSIGN_OR_RETURN(overlapped_call.hEvent, utils::CreateManualResetEvent());
  absl::MutexLock l(&call_state_mutex_);
  call_state_ = overlapped_call;

  PPN_ASSIGN_OR_RETURN(stop_pipe_event_, utils::CreateManualResetEvent());
  return absl::OkStatus();
}

void NamedPipe::FlushPipe(){
  // Wait until all the messages are read
  FlushFileBuffers(pipe_);
}

void NamedPipe::Close() {
  if (!CancelIoEx(pipe_, nullptr)) {
    LOG(WARNING) << utils::GetStatusForError("Failed while cancelling IO",
                                             GetLastError());
  }
  CloseHandle(read_state_.hEvent);
  CloseHandle(connection_state_.hEvent);
  CloseHandle(write_state_.hEvent);
  absl::MutexLock l(&call_state_mutex_);
  CloseHandle(call_state_.hEvent);
  CloseHandle(pipe_);
  CloseHandle(stop_pipe_event_);
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
