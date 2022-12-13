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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_PPN_LOG_SINK_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_PPN_LOG_SINK_H_

#include "privacy/net/krypton/desktop/windows/logging/file_logger.h"
#include "third_party/absl/log/log_sink.h"
#include "third_party/absl/log/log_sink_registry.h"

namespace privacy {
namespace krypton {
namespace windows {

class PpnLogSink : absl::LogSink {
 public:
  explicit PpnLogSink(FileLogger* logger) : logger_(logger) {
    absl::AddLogSink(this);
  }
  ~PpnLogSink() override { absl::RemoveLogSink(this); }
  PpnLogSink(const PpnLogSink&) = delete;
  PpnLogSink& operator=(const PpnLogSink&) = delete;
  void Send(const absl::LogEntry& entry) override;

 private:
  FileLogger* logger_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_PPN_LOG_SINK_H_
