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

#include "privacy/net/krypton/desktop/windows/logging/ppn_log_sink.h"

#include <string>

#include "third_party/absl/log/log_entry.h"

namespace privacy {
namespace krypton {
namespace windows {

void PpnLogSink::Send(const absl::LogEntry &entry) {
  if (logger_ == nullptr) return;
  auto message = entry.text_message_with_prefix();
  auto log_result = logger_->Log(message);
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
