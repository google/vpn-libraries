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

#include "privacy/net/krypton/desktop/windows/local_secure_storage_windows.h"

// windows.h must be #include'd before wincred.h as it defines several types
// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on

#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"

namespace privacy {
namespace krypton {
namespace desktop {
namespace {
std::string FormTarget(absl::string_view keyNamespace, absl::string_view key) {
  return absl::StrCat(keyNamespace, ":", key);
}
}  // namespace

absl::Status LocalSecureStorageWindows::StoreData(absl::string_view key,
                                                  absl::string_view value) {
  std::string target = FormTarget(kPpnRefreshKeyPrefix, key);
  PPN_RETURN_IF_ERROR(DeleteData(key));
  CREDENTIALA credential = {0};
  credential.Type = CRED_TYPE_GENERIC;
  credential.TargetName = const_cast<char*>(target.c_str());
  credential.CredentialBlobSize = (DWORD)(value.size());
  credential.CredentialBlob = (LPBYTE)(value.data());
  credential.Persist = CRED_PERSIST_ENTERPRISE;
  if (!CredWriteA(&credential, 0)) {
    return windows::utils::GetStatusForError(
        "failed to store data to local storage", GetLastError());
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> LocalSecureStorageWindows::FetchData(
    absl::string_view key) {
  std::string target = FormTarget(kPpnRefreshKeyPrefix, key);
  PCREDENTIALA credential;
  bool status = CredReadA(target.c_str(), CRED_TYPE_GENERIC, 0, &credential);
  if (!status) {
    DWORD error = GetLastError();
    auto message = absl::StrCat("failed to find data with key: ", key);
    return windows::utils::GetStatusForError(message, error);
  }
  return std::string(reinterpret_cast<char*>(credential->CredentialBlob),
                     credential->CredentialBlobSize);
}

absl::Status LocalSecureStorageWindows::DeleteData(absl::string_view key) {
  std::string target = FormTarget(kPpnRefreshKeyPrefix, key);
  bool status = CredDeleteA(target.c_str(), CRED_TYPE_GENERIC, 0);
  if (!status) {
    const DWORD error = GetLastError();
    if (error != ERROR_NOT_FOUND) {
      auto message = absl::StrCat("failed to delete resource with key: ", key);
      return windows::utils::GetStatusForError(message, error);
    }
  }
  return absl::OkStatus();
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
