// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/desktop/windows/utils/file_utils.h"

#include <windows.h>

#include <filesystem>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

constexpr char kAppPath[] = "Google\\GoogleOne";

absl::StatusOr<std::filesystem::path> CreateLocalAppDataPath() {
  constexpr int kEnvVarBufferSize = 1024;
  wchar_t temp_buffer[kEnvVarBufferSize];
  if (::GetEnvironmentVariableW(L"LocalAppData", temp_buffer,
                                kEnvVarBufferSize) == 0) {
    LOG(ERROR) << "LocalAppData unknown";
    return absl::InternalError("LocalAppData unknown");
  }

  std::filesystem::path app_data_path(temp_buffer);
  auto base_path = app_data_path / kAppPath;

  auto status = CreateDirectoryRecursively(base_path);
  if (!status.ok()) {
    return absl::InternalError("Could not create directory");
  }
  return base_path;
}

absl::Status CreateDirectoryRecursively(
    const std::filesystem::path& directory) {
  DWORD fileAttributes = ::GetFileAttributesW(directory.c_str());
  if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
    // Recursively do it all again for the parent directory, if any
    if (directory.has_parent_path()) {
      auto parent = directory.parent_path();
      auto status = CreateDirectoryRecursively(parent);
      if (!status.ok()) return status;
    }
    // Create the last directory on the path (the recursive calls will have
    // taken care of the parent directories by now)
    BOOL result = ::CreateDirectoryW(directory.c_str(), nullptr);
    if (result == FALSE) {
      LOG(ERROR) << "Could not create directory: " << directory.c_str();
      return absl::InternalError("Could not create directory");
    }

  } else {  // Specified directory name already exists as a file or directory
    bool isDirectoryOrJunction =
        ((fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) ||
        ((fileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);

    if (!isDirectoryOrJunction) {
      LOG(ERROR)
          << "Could not create directory because a file with the same name "
             "exists";
      return absl::InternalError("Could not create directory");
    }
  }
  return absl::OkStatus();
}

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
