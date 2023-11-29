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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "privacy/net/common/proto/beryllium.proto.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {
namespace utils {

// Returns the JSON formatted string representing the JSON object.
std::string JsonToString(const nlohmann::json& json_obj);

// Returns the JSON object representation of the string. The string should be in
// JSON format.
absl::StatusOr<nlohmann::json> StringToJson(absl::string_view json_str);

// Returns the desired integer value from the JSON object. If there is no value
// for the provided key the returned optional will be empty.
absl::StatusOr<std::optional<int64_t>> JsonGetInt64(
    const nlohmann::json& json_obj, absl::string_view json_key);

// Returns the desired string value from the JSON object. If there is no value
// for the provided key the returned optional will be empty.
absl::StatusOr<std::optional<std::string>> JsonGetString(
    const nlohmann::json& json_obj, absl::string_view json_key);

// Decodes the desired string value from the JSON object from base64 and returns
// it. If there is no value for the provided key the returned optional will be
// empty.
absl::StatusOr<std::optional<std::string>> JsonGetBytes(
    const nlohmann::json& json_obj, absl::string_view json_key);

// Returns the desired string array from the JSON object. If there is no value
// for the provided key the returned optional will be empty.
absl::StatusOr<std::optional<std::vector<std::string>>> JsonGetStringArray(
    nlohmann::json json_obj, absl::string_view key);

// Returns the desired IpRange array from the JSON object. If there is no value
// for the provided key the returned optional will be empty.
absl::StatusOr<std::optional<std::vector<net::common::proto::IpRange>>>
JsonGetIpRangeArray(nlohmann::json json_obj, absl::string_view key);

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_JSON_UTIL_H_
