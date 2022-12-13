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

#include "privacy/net/krypton/desktop/windows/utils/event.h"

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

absl::StatusOr<HANDLE> CreateManualResetEvent() {
  auto handle =
      CreateEvent(NULL,   // handle can't be inherited by child processes
                  TRUE,   // handle must be manually reset with ResetEvent()
                  FALSE,  // initial state is nonsignaled
                  nullptr);
  if (handle == nullptr) {
    return GetStatusForError("CreateEvent failed", GetLastError());
  }
  return handle;
}

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
