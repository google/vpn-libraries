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

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"

#include <aclapi.h>
#include <sddl.h>
#include <windows.h>

#include <memory>
#include <string>

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

static constexpr const auto kPipeBufferSize = 4096;
static constexpr const auto kPipeWaitTime = absl::Minutes(2);

absl::StatusOr<std::unique_ptr<NamedPipeInterface>>
NamedPipeFactory::ConnectToPipeOnServer(const std::string& pipe_name) const {
  do {
    if (WaitNamedPipe(pipe_name.c_str(), NMPWAIT_USE_DEFAULT_WAIT)) {
      HANDLE pipe =
          CreateFile(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                     nullptr, OPEN_EXISTING,
                     FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
                         SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY,
                     nullptr);
      if (pipe != INVALID_HANDLE_VALUE) {
        DWORD pipe_mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &pipe_mode,
                                     nullptr /* max collection count */,
                                     nullptr /* collect data timeout */)) {
          return privacy::krypton::windows::utils::GetStatusForError(
              "Setting Named State for pipe failed with error", GetLastError());
        }
        auto named_pipe = std::make_unique<NamedPipe>(pipe);
        PPN_RETURN_IF_ERROR(named_pipe->Initialize());
        return named_pipe;
      }
    }
    LOG(WARNING) << utils::GetStatusForError(
        absl::Substitute("Connecting to pipe $0 failed with", pipe_name),
        GetLastError());
  } while (GetLastError() == ERROR_PIPE_BUSY);
  return utils::GetStatusForError(
      absl::Substitute("Connecting to pipe $0 failed with", pipe_name),
      GetLastError());
}

absl::StatusOr<std::unique_ptr<NamedPipeInterface>>
NamedPipeFactory::CreateNamedPipeInstance(const std::string& pipe_name) const {
  PPN_ASSIGN_OR_RETURN(auto security_descriptor, GetSecurityDescriptor());
  absl::Cleanup free_security_descriptor = [security_descriptor] {
    LocalFree(security_descriptor);
  };

  SECURITY_ATTRIBUTES security_attributes;
  memset(&security_attributes, 0, sizeof(security_attributes));
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.lpSecurityDescriptor = security_descriptor;
  security_attributes.bInheritHandle = TRUE;

  HANDLE pipe_handle = CreateNamedPipe(
      pipe_name.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, kPipeBufferSize, kPipeBufferSize,
      static_cast<DWORD>(absl::ToInt64Milliseconds(kPipeWaitTime)),
      &security_attributes);
  if (pipe_handle == INVALID_HANDLE_VALUE) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Pipe initialization failed with error", GetLastError());
  }
  auto named_pipe = std::make_unique<NamedPipe>(pipe_handle);
  PPN_RETURN_IF_ERROR(named_pipe->Initialize());
  return named_pipe;
}

absl::StatusOr<PSECURITY_DESCRIPTOR> NamedPipeFactory::GetSecurityDescriptor()
    const {
  PSECURITY_DESCRIPTOR base_sec_desc;
  // SDDL giving LocalSystem i.e. S-1-5-18 SID File Read and File Write (FRFW)
  // DACL and Mandatory Level (ML) no write up(NW) SACL for
  // low integrity processes (LW).
  std::string sddl("D:(A;;FRFW;;;S-1-5-18)S:(ML;;NW;;;LW)");
  if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
          sddl.c_str(), SDDL_REVISION_1, &base_sec_desc, nullptr)) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "ConvertStringSecurityDescriptorToSecurityDescriptor failed",
        GetLastError());
  }
  // ACE for current user to have File All Access DACL.
  char sid_buffer[SECURITY_MAX_SID_SIZE];
  DWORD sid_buffer_size = sizeof(sid_buffer);
  if (CreateWellKnownSid(WinSelfSid, nullptr, sid_buffer, &sid_buffer_size) ==
      0) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "Failed to create SID for Self User", GetLastError());
  }

  EXPLICIT_ACCESS access_descriptor;

  ZeroMemory(&access_descriptor, sizeof(access_descriptor));
  access_descriptor.grfAccessPermissions = FILE_ALL_ACCESS;
  access_descriptor.grfAccessMode = GRANT_ACCESS;
  access_descriptor.grfInheritance = NO_INHERITANCE;
  access_descriptor.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access_descriptor.Trustee.ptstrName = sid_buffer;

  PSECURITY_DESCRIPTOR user_sec_desc;
  ULONG user_sec_desc_size;
  DWORD error = BuildSecurityDescriptor(nullptr, nullptr, 1, &access_descriptor,
                                        0, nullptr, base_sec_desc,
                                        &user_sec_desc_size, &user_sec_desc);
  if (error != ERROR_SUCCESS) {
    return privacy::krypton::windows::utils::GetStatusForError(
        "BuildSecurityDescriptor failed", GetLastError());
  }
  return user_sec_desc;
}
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
