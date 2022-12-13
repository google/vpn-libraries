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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_FILE_UTILS_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_FILE_UTILS_H_

#include <filesystem>
#include <string>

#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

// Creates the local app data path to store krypton logs in.
absl::StatusOr<std::filesystem::path> CreateLocalAppDataPath();
// Creates directory at the specified path recursively
absl::Status CreateDirectoryRecursively(const std::filesystem::path& directory);

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_FILE_UTILS_H_
