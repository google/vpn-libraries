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

#include "privacy/net/krypton/utils/json_util.h"

#include <string>

#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace utils {

std::string JsonToString(const nlohmann::json& json_obj) {
  if (json_obj.is_null()) return "";

  // TODO: Update to better handle invalid characters
  return json_obj.dump(-1, ' ', false,
                       nlohmann::detail::error_handler_t::ignore);
}

absl::StatusOr<nlohmann::json> StringToJson(absl::string_view json_str) {
  nlohmann::json json_obj = nlohmann::json::parse(json_str, nullptr, false);

  if (json_obj.is_discarded()) {
    return absl::InternalError("Failed to convert string to JSON object.");
  }
  return json_obj;
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
