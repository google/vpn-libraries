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

#include "privacy/net/krypton/desktop/windows/utils/error.h"

#include <windows.h>

#include "google/protobuf/any.proto.h"
#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_format.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

std::string GetErrorMessage(DWORD error) {
  // The 8-bit versions of FormatMessage don't use UTF-8, so if we want a UTF-8
  // string, we have to use FormatMessageW explicitly and convert the result.
  LPWSTR message = nullptr;
  // This API requires casting the LPTSTR* to an LPTSTR if
  // FORMAT_MESSAGE_ALLOCATE_BUFFER is used.
  DWORD result = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&message,
      0, NULL);
  if (result == 0 || message == nullptr) {
    if (GetLastError() == ERROR_MR_MID_NOT_FOUND) {
      // This particular error code means that the message string couldn't be
      // found. That usually means that the code is from a DLL rather than the
      // OS itself. We don't know which HMODULE to pass in, so better to just
      // return the code itself as a string.
      return absl::StrFormat("Error 0x%08x", error);
    }

    // FormatMessage failed. We could get the reason for the failure, but if we
    // try to convert it to a string, we might accidentally create an infinite
    // recursion, so just report the error number.
    return absl::StrFormat("Error 0x%08x [unable to format message: 0x%08x]",
                           error, GetLastError());
  }
  std::string s = WcharToString(message);
  LocalFree(message);
  s = absl::StrFormat("Error 0x%08x: %s", error, s);
  return s;
}

absl::Status GetStatusForError(absl::string_view prefix, DWORD error) {
  std::string message = GetErrorMessage(error);
  if (!prefix.empty()) {
    message = absl::StrCat(prefix, ": ", message);
  }
  if (error == ERROR_NOT_FOUND) {
    return absl::NotFoundError(message);
  }
  if (error == ERROR_NO_MORE_ITEMS) {
    return absl::ResourceExhaustedError(message);
  }
  return absl::InternalError(message);
}

google::rpc::Status GetRpcStatusforStatus(absl::Status status) {
  google::rpc::Status rpc_status;
  rpc_status.set_code(static_cast<google::rpc::Code>(status.code()));
  rpc_status.set_message(status.message());
  status.ForEachPayload([&](absl::string_view type_url, absl::Cord payload) {
    google::protobuf::Any* any = rpc_status.add_details();
    any->set_type_url(type_url);
    any->set_value(payload);
  });
  return rpc_status;
}

absl::Status GetStatusFromRpcStatus(google::rpc::Status rpc_status) {
  absl::Status status(static_cast<absl::StatusCode>(rpc_status.code()),
                      rpc_status.message());
  for (const google::protobuf::Any& detail : rpc_status.details()) {
    status.SetPayload(detail.type_url(), detail.value());
  }
  return status;
}

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
