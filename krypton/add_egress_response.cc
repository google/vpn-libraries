// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/add_egress_response.h"

#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace {
// Fill JsonArray containing string value to std::vector<string>
absl::Status CopyToVector(Json::Value json_array_value, const std::string& key,
                          std::vector<std::string>* output) {
  if (!json_array_value.isMember(key)) {
    return absl::NotFoundError(absl::StrCat("Cannot find ", key));
  }
  auto key_value_array = json_array_value[key];
  if (!key_value_array.isArray()) {
    return absl::InvalidArgumentError(
        absl::StrCat(key, " is not of array type"));
  }

  for (const auto& i : key_value_array) {
    // We only return the first index of type string.
    output->push_back(i.asString());
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> JsonValueToString(Json::Value value,
                                              const std::string& key) {
  if (value != Json::Value::null && value.isMember(key)) {
    return value[key].asString();
  }
  return absl::NotFoundError(absl::StrCat("Cannot find ", key));
}

absl::StatusOr<absl::Time> JsonTimestampToMilliseconds(
    Json::Value timestampValue) {
  absl::Time time;
  std::string error;
  if (!absl::ParseTime(absl::RFC3339_full, timestampValue.asString(), &time,
                       &error)) {
    LOG(ERROR) << "Unable to parse timestamp [" << timestampValue.asString()
               << "]";
    return absl::InvalidArgumentError("Unable to parse timestamp [" +
                                      timestampValue.asString() + "]");
  }
  return time;
}

}  // namespace

absl::Status AddEgressResponse::DecodeFromJsonObject(
    absl::string_view json_string) {
  Json::Reader reader;
  Json::Value root;
  auto parsing_status = reader.parse(std::string(json_string), root);
  if (!parsing_status) {
    parsing_status_ = absl::FailedPreconditionError(
        "Cannot parse AddEgressResponse response");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }
  for (auto it = root.begin(); it != root.end(); ++it) {
    Json::FastWriter writer;
    if (it.name() == JsonKeys::kStatusKey) {
      parsing_status_ = http_response_.DecodeFromJsonObject(*it);
      if (!parsing_status_.ok()) {
        LOG(ERROR) << parsing_status_;
        return parsing_status_;
      }
    } else if (it.name() == JsonKeys::kHeadersKey) {
      parsing_status_ =
          http_response_.MutableHeader()->DecodeFromJsonObject(*it);
      if (!parsing_status_.ok()) {
        LOG(ERROR) << parsing_status_;
        return parsing_status_;
      }
    } else if (it.name() == JsonKeys::kJsonBodyKey) {
      parsing_status_ = DecodeJsonBody(*it);
      if (!parsing_status_.ok()) {
        LOG(ERROR) << parsing_status_;
        return parsing_status_;
      }
    }
  }
  return parsing_status_ = absl::OkStatus();
}

absl::Status AddEgressResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body was not a JSON object.");
  }
  if (value.isMember(JsonKeys::kBridge)) {
    bridge_dataplane_response_ =
        absl::make_unique<BridgeDataPlaneResponse>(value[JsonKeys::kBridge]);
    return absl::OkStatus();
  }
  if (value.isMember(JsonKeys::kPpnDataplane)) {
    ppn_dataplane_response_ =
        absl::make_unique<PpnDataPlaneResponse>(value[JsonKeys::kPpnDataplane]);
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError(
      "No datapath found in the AddEgressResponse [Bridge|PPN].");
}

absl::StatusOr<uint64> BridgeDataPlaneResponse::GetSessionId() const {
  if (bridge_data_plane_response_json_.isMember(JsonKeys::kSessionId)) {
    return bridge_data_plane_response_json_[JsonKeys::kSessionId].asInt();
  }
  return absl::InvalidArgumentError("No SessionId found in the response");
}

absl::StatusOr<std::string> BridgeDataPlaneResponse::GetSessionToken() const {
  return JsonValueToString(bridge_data_plane_response_json_,
                           JsonKeys::kSessionToken);
}

absl::StatusOr<std::string> BridgeDataPlaneResponse::GetClientCryptoKey()
    const {
  return JsonValueToString(bridge_data_plane_response_json_,
                           JsonKeys::kClientCryptoKey);
}

absl::StatusOr<std::string> BridgeDataPlaneResponse::GetServerCryptoKey()
    const {
  return JsonValueToString(bridge_data_plane_response_json_,
                           JsonKeys::kServerCryptoKey);
}

absl::StatusOr<std::vector<std::string>> BridgeDataPlaneResponse::GetIpRanges()
    const {
  std::vector<std::string> ip_ranges;
  auto status = CopyToVector(bridge_data_plane_response_json_,
                             JsonKeys::kIpRanges, &ip_ranges);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return status;
  }
  return ip_ranges;
}

absl::StatusOr<std::vector<std::string>>
BridgeDataPlaneResponse::GetDataplaneSockAddresses() const {
  std::vector<std::string> data_plane_sock_addresses;
  auto status =
      CopyToVector(bridge_data_plane_response_json_,
                   JsonKeys::kDataplaneSockAddr, &data_plane_sock_addresses);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return status;
  }
  return data_plane_sock_addresses;
}

absl::StatusOr<std::vector<std::string>>
BridgeDataPlaneResponse::GetControlPlaneSockAddresses() const {
  std::vector<std::string> control_plane_sock_addresses;
  auto status = CopyToVector(bridge_data_plane_response_json_,
                             JsonKeys::kControlPlaneSockAddresses,
                             &control_plane_sock_addresses);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return status;
  }
  return control_plane_sock_addresses;
}

absl::StatusOr<std::string> BridgeDataPlaneResponse::GetError() const {
  return JsonValueToString(bridge_data_plane_response_json_, JsonKeys::kError);
}

BridgeDataPlaneResponse::BridgeDataPlaneResponse(Json::Value response_json)
    : bridge_data_plane_response_json_(response_json) {}

absl::StatusOr<std::vector<std::string>>
PpnDataPlaneResponse::GetUserPrivateIp() const {
  std::vector<std::string> ip_ranges;

  if (!ppn_data_plane_response_json_.isMember(JsonKeys::kUserPrivateIp) ||
      !ppn_data_plane_response_json_[JsonKeys::kUserPrivateIp].isArray() ||
      ppn_data_plane_response_json_[JsonKeys::kUserPrivateIp].empty()) {
    return absl::InvalidArgumentError(
        "No kUserPrivateIp [user_private_ip] in PPN Response.");
  }
  for (const auto& private_ip :
       ppn_data_plane_response_json_[JsonKeys::kUserPrivateIp]) {
    if (private_ip.isMember(JsonKeys::kIpv4)) {
      PPN_ASSIGN_OR_RETURN(auto ipv4,
                           JsonValueToString(private_ip, JsonKeys::kIpv4));
      ip_ranges.push_back(ipv4);
    }

    if (private_ip.isMember(JsonKeys::kIpv6)) {
      PPN_ASSIGN_OR_RETURN(auto ipv6,
                           JsonValueToString(private_ip, JsonKeys::kIpv6));
      ip_ranges.push_back(ipv6);
    }
  }
  if (ip_ranges.empty()) {
    return absl::InvalidArgumentError(
        "No kUserPrivateIp [user_private_ip] in PPN Response.");
  }
  return ip_ranges;
}

absl::StatusOr<std::vector<std::string>>
PpnDataPlaneResponse::GetEgressPointSockAddr() const {
  std::vector<std::string> sock_addrs;
  auto status = CopyToVector(ppn_data_plane_response_json_,
                             JsonKeys::kEgressPointSockAddr, &sock_addrs);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return status;
  }
  return sock_addrs;
}

absl::StatusOr<std::string> PpnDataPlaneResponse::GetEgressPointPublicKey()
    const {
  return JsonValueToString(ppn_data_plane_response_json_,
                           JsonKeys::kEgressPointPublicValue);
}

absl::StatusOr<std::string> PpnDataPlaneResponse::GetServerNonce() const {
  return JsonValueToString(ppn_data_plane_response_json_,
                           JsonKeys::kServerNonce);
}

absl::StatusOr<uint32> PpnDataPlaneResponse::GetUplinkSpi() const {
  return ppn_data_plane_response_json_[JsonKeys::kUplinkSpi].asInt();
}

absl::StatusOr<absl::Time> PpnDataPlaneResponse::GetExpiry() const {
  return JsonTimestampToMilliseconds(
      ppn_data_plane_response_json_[JsonKeys::kExpiry]);
}

PpnDataPlaneResponse::PpnDataPlaneResponse(Json::Value ppn_json)
    : ppn_data_plane_response_json_(ppn_json) {}
}  // namespace krypton
}  // namespace privacy
