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

#include "privacy/net/krypton/utils/network_info.h"

#include <string>

#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

std::string NetworkTypeDebugString(const NetworkInfo& network_info) {
  if (!network_info.has_network_type()) {
    return "<UNSET>";
  }
  switch (network_info.network_type()) {
    case NetworkType::UNKNOWN_TYPE:
      return "UNKNOWN";
    case NetworkType::WIFI:
      return "WIFI";
    case NetworkType::CELLULAR:
      return "CELLULAR";
    default:
      return "<INVALID_TYPE>";
  }
}

std::string AddressFamilyDebugString(const NetworkInfo& network_info) {
  if (!network_info.has_address_family()) {
    return "<UNSET>";
  }
  switch (network_info.address_family()) {
    case NetworkInfo::V4:
      return "V4";
    case NetworkInfo::V6:
      return "V6";
    case NetworkInfo::V4V6:
      return "V4V6";
    default:
      return "<INVALID_FAMILY>";
  }
}

}  // namespace

std::string NetworkInfoDebugString(const NetworkInfo& network_info) {
  return absl::StrCat(
      "NetworkInfo{type = ", NetworkTypeDebugString(network_info),
      ", family = ", AddressFamilyDebugString(network_info), "}");
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
