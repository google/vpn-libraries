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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/json/include/nlohmann/detail/output/serializer.hpp"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

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

absl::StatusOr<std::optional<int64_t>> JsonGetInt64(
    const nlohmann::json& json_obj, absl::string_view json_key) {
  auto value_it = json_obj.find(json_key);
  if (value_it == json_obj.end()) {
    return std::nullopt;
  }
  if (!value_it->is_number_integer()) {
    return absl::InvalidArgumentError(
        absl::StrCat(json_key, " is not an integer"));
  }
  return *value_it;
}

absl::StatusOr<std::optional<std::string>> JsonGetString(
    const nlohmann::json& json_obj, absl::string_view json_key) {
  auto value_it = json_obj.find(json_key);
  if (value_it == json_obj.end()) {
    return std::nullopt;
  }
  if (!value_it->is_string()) {
    return absl::InvalidArgumentError(
        absl::StrCat(json_key, " is not a string"));
  }
  return *value_it;
}

absl::StatusOr<std::optional<std::string>> JsonGetBytes(
    const nlohmann::json& json_obj, absl::string_view json_key) {
  auto value_it = json_obj.find(json_key);
  if (value_it == json_obj.end()) {
    return std::nullopt;
  }
  if (!value_it->is_string()) {
    return absl::InvalidArgumentError(
        absl::StrCat(json_key, " is not a string"));
  }
  std::string decoded;
  if (!absl::Base64Unescape(std::string(*value_it), &decoded)) {
    return absl::InvalidArgumentError(
        absl::StrCat(json_key, " is not valid base64"));
  }
  return decoded;
}

absl::StatusOr<std::optional<std::vector<std::string>>> JsonGetStringArray(
    nlohmann::json json_obj, absl::string_view key) {
  auto value_it = json_obj.find(key);
  if (value_it == json_obj.end()) {
    // Proto 3 doesn't distinguish between a missing field and an empty field,
    // so if it's missing, we won't count that as an error.
    return std::nullopt;
  }
  if (!value_it->is_array()) {
    return absl::InvalidArgumentError(
        absl::StrCat(key, " is not of array type"));
  }

  std::vector<std::string> output;
  for (const auto& element : *value_it) {
    if (!element.is_string()) {
      return absl::InvalidArgumentError(
          absl::StrCat(key, " element is not of type string"));
    }
    output.push_back(element);
  }
  return output;
}

absl::StatusOr<std::optional<std::vector<net::common::proto::IpRange>>>
JsonGetIpRangeArray(nlohmann::json json_obj, absl::string_view key) {
  auto value_it = json_obj.find(key);
  if (value_it == json_obj.end()) {
    // Proto 3 doesn't distinguish between a missing field and an empty field,
    // so if it's missing, we won't count that as an error.
    return std::nullopt;
  }
  if (!value_it->is_array()) {
    return absl::InvalidArgumentError(
        absl::StrCat(key, " is not of array type"));
  }

  std::vector<net::common::proto::IpRange> output;
  for (const auto& ip_str : *value_it) {
    if (!ip_str.is_object()) {
      return absl::InvalidArgumentError(
          absl::StrCat(key, " element is not of type object"));
    }
    if (ip_str.contains(JsonKeys::kIpv4)) {
      net::common::proto::IpRange ip_range;
      ip_range.set_ipv4_range(std::string(ip_str[JsonKeys::kIpv4]));
      output.push_back(ip_range);
    }
    if (ip_str.contains(JsonKeys::kIpv6)) {
      net::common::proto::IpRange ip_range;
      ip_range.set_ipv6_range(std::string(ip_str[JsonKeys::kIpv6]));
      output.push_back(ip_range);
    }
  }
  return output;
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
