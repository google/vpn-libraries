/*
 * Copyright (C) 2021 Google Inc.
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

#ifndef IPHONE_SHARED_PPN_CLASSES_PPNLOGSINK_H_
#define IPHONE_SHARED_PPN_CLASSES_PPNLOGSINK_H_

#include <string>

#include "base/logging.h"
#include "googlemac/iPhone/Shared/PPN/API/PPNLogging.h"

namespace privacy {
namespace krypton {

// Log sink that delivers C++ logs to the device console.
class PPNLogSink : absl::LogSink {
 public:
  PPNLogSink() { absl::AddLogSink(this); }

  ~PPNLogSink() override { absl::RemoveLogSink(this); }

  void SetLogger(id<PPNLogging> logger) { logger_ = logger; }

  void Send(const absl::LogEntry &entry) override;

 private:
  id<PPNLogging> logger_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // IPHONE_SHARED_PPN_CLASSES_PPNLOGSINK_H_
