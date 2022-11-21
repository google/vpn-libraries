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
#ifndef PRIVACY_NET_KRYPTON_UTILS_URL_H_
#define PRIVACY_NET_KRYPTON_UTILS_URL_H_

#include <string>
#include <utility>
#include <vector>

#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace utils {

/**
 * Basic URL encoding class that basically just appends query parameters onto
 * a given base_url.
 */
class URL {
 public:
  explicit URL(absl::string_view base) : url_base_(base) {}
  void AddQueryComponent(std::string key, std::string value);
  std::string AssembleString();

 private:
  std::string url_base_;
  std::vector<std::pair<std::string, std::string>> params_vec_;
  static std::string EscapeCharsIfNecessary(absl::string_view str);

  static bool ShouldEscape(char c);
};

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_URL_H_
