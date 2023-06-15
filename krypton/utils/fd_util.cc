// Copyright 2023 Google LLC
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

#include "privacy/net/krypton/utils/fd_util.h"

#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"

namespace privacy {
namespace krypton {

absl::Status CloseFd(int fd) {
  // Retry close operation if it is interrupted.
  int ret;
  do {
    ret = close(fd);
  } while (ret < 0 && errno == EINTR);

  if (ret < 0) {
    return absl::InternalError(
        absl::StrCat("Error closing fd=", fd, ": ", strerror(errno)));
  }
  return absl::OkStatus();
}

}  // namespace krypton
}  // namespace privacy
