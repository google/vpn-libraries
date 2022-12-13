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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_ERROR_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_ERROR_H_

#include <windows.h>

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

// Converts the given Windows error into an absl::Status using FormatMessage.
absl::Status GetStatusForError(absl::string_view prefix, DWORD error);

google::rpc::Status GetRpcStatusforStatus(absl::Status status);

absl::Status GetStatusFromRpcStatus(google::rpc::Status rpc_status);

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_ERROR_H_
