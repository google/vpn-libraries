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
#include "privacy/net/krypton/utils/url.h"

#include <iostream>
#include <string>
#include <utility>

#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace utils {

void URL::AddQueryComponent(std::string key, std::string value) {
  params_vec_.emplace_back(std::make_pair(EscapeCharsIfNecessary(key),
                                          EscapeCharsIfNecessary(value)));
}

std::string URL::AssembleString() {
  std::string url = url_base_;
  if (!params_vec_.empty()) {
    url += "?";
    for (int i = 0; i < params_vec_.size(); i++) {
      if (params_vec_[i].first.empty()) {
        continue;
      }
      url += ((i > 0 ? "&" : "") + params_vec_[i].first + "=" +
              params_vec_[i].second);
    }
  }
  return url;
}

std::string URL::EscapeCharsIfNecessary(absl::string_view str) {
  std::string final_str;
  int start_pos = 0;
  for (int i = 0; i < str.size(); i++) {
    char ch = str[i];
    if (ShouldEscape(ch)) {
      absl::StrAppend(&final_str, str.substr(start_pos, i - start_pos),
                      absl::StrFormat("%%%02X", ch));
      start_pos = i + 1;
    }
  }
  if (start_pos < str.size()) {
    absl::StrAppend(&final_str, str.substr(start_pos, str.size() - start_pos));
  }
  return final_str;
}

bool URL::ShouldEscape(char c) {
  return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           c == '~');
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
