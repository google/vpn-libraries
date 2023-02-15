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

#ifndef PRIVACY_NET_KRYPTON_UTILS_JSON_UTIL_H_
#define PRIVACY_NET_KRYPTON_UTILS_JSON_UTIL_H_

#include <string>

#include "third_party/absl/status/statusor.h"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {
namespace utils {

std::string JsonToString(const nlohmann::json& json_obj);

absl::StatusOr<nlohmann::json> StringToJson(absl::string_view json_str);

absl::StatusOr<std::string> JsonGetString(const nlohmann::json& value,
                                          const std::string& json_key);

absl::StatusOr<int64_t> JsonGetInt(const nlohmann::json& value,
                                   const std::string& json_key);

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_JSON_UTIL_H_
