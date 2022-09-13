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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNLogSink.h"

#include <Foundation/Foundation.h>

#include "third_party/absl/log/log_entry.h"

namespace privacy {
namespace krypton {

void PPNLogSink::Send(const absl::LogEntry &entry) {
  // PPNLog will serve as a filter that can be used in the device console.
  NSLog(@"PPNLog: %s", entry.text_message_with_prefix_and_newline_c_str());

  if (logger_ == nullptr) return;
  NSString *message = [NSString stringWithCString:entry.text_message_with_prefix_and_newline_c_str()
                                         encoding:NSUTF8StringEncoding];
  [logger_ log:message];
}

}  // namespace krypton
}  // namespace privacy
