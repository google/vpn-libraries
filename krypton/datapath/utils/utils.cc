// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/utils/utils.h"

#include <algorithm>
#include <string>

#include "third_party/absl/strings/ascii.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace utils {

std::string StringToHexASCIIDump(absl::string_view in_buffer) {
  int offset = 0;
  const char* buf = in_buffer.data();
  int bytes_remaining = in_buffer.size();
  std::string s;  // our output
  const char* p = buf;
  while (bytes_remaining > 0) {
    const int line_bytes = std::min(bytes_remaining, 16);
    absl::StrAppendFormat(&s, "0x%04x:  ", offset);  // Do the line header
    for (int i = 0; i < 16; ++i) {
      if (i < line_bytes) {
        absl::StrAppendFormat(&s, "%02x", p[i]);
      } else {
        s += "  ";  // two-space filler instead of two-space hex digits
      }
      if ((i % 2) != 0) s += ' ';
    }
    s += ' ';
    for (int i = 0; i < line_bytes; ++i) {  // Do the ASCII dump
      s += absl::ascii_isgraph(p[i]) ? p[i] : '.';
    }

    bytes_remaining -= line_bytes;
    offset += line_bytes;
    p += line_bytes;
    s += '\n';
  }
  return s;
}

}  // namespace utils
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
