// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/add_egress_response.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {

using net::common::proto::PpnDataplaneResponse;
using net::common::proto::PpnIkeResponse;

namespace {

absl::StatusOr<PpnDataplaneResponse> ParsePpnDataplaneResponse(
    nlohmann::json json) {
  PpnDataplaneResponse response;

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::vector<net::common::proto::IpRange>> user_private_ip,
      utils::JsonGetIpRangeArray(json, JsonKeys::kUserPrivateIp));
  if (user_private_ip) {
    response.mutable_user_private_ip()->Assign(user_private_ip->begin(),
                                               user_private_ip->end());
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::vector<std::string>> egress_point_sock_addr,
      utils::JsonGetStringArray(json, JsonKeys::kEgressPointSockAddr));
  if (egress_point_sock_addr) {
    response.mutable_egress_point_sock_addr()->Assign(
        egress_point_sock_addr->begin(), egress_point_sock_addr->end());
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::string> egress_point_public_value,
      utils::JsonGetBytes(json, JsonKeys::kEgressPointPublicValue));
  if (egress_point_public_value) {
    response.set_egress_point_public_value(*egress_point_public_value);
  }

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> server_nonce,
                       utils::JsonGetBytes(json, JsonKeys::kServerNonce));
  if (server_nonce) {
    response.set_server_nonce(*server_nonce);
  }

  PPN_ASSIGN_OR_RETURN(std::optional<int64_t> uplink_spi,
                       utils::JsonGetInt64(json, JsonKeys::kUplinkSpi));
  if (uplink_spi) {
    response.set_uplink_spi(*uplink_spi);
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::vector<std::string>> mss_detection_sock_addr,
      utils::JsonGetStringArray(json, JsonKeys::kMssDetectionSockAddr));
  if (mss_detection_sock_addr) {
    response.mutable_mss_detection_sock_addr()->Assign(
        mss_detection_sock_addr->begin(), mss_detection_sock_addr->end());
  }

  // This is the only Timestamp value, so there's no need for a helper macro.
  if (json.contains(JsonKeys::kExpiry)) {
    if (!json[JsonKeys::kExpiry].is_string()) {
      return absl::InvalidArgumentError("expiry timestamp is not a string");
    }
    std::string value = json[JsonKeys::kExpiry];
    PPN_ASSIGN_OR_RETURN(auto expiry, utils::ParseTimestamp(value));

    PPN_RETURN_IF_ERROR(utils::ToProtoTime(expiry, response.mutable_expiry()));
  }

  return response;
}

absl::StatusOr<PpnIkeResponse> ParseIkeResponse(nlohmann::json json) {
  PpnIkeResponse response;

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> client_id,
                       utils::JsonGetBytes(json, JsonKeys::kClientId));
  if (client_id) {
    response.set_client_id(*client_id);
  }

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> shared_secret,
                       utils::JsonGetBytes(json, JsonKeys::kSharedSecret));
  if (shared_secret) {
    response.set_shared_secret(*shared_secret);
  }

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> server_address,
                       utils::JsonGetString(json, JsonKeys::kServerAddress));
  if (server_address) {
    response.set_server_address(*server_address);
  }

  return response;
}

}  // namespace

absl::Status AddEgressResponse::DecodeFromProto(const HttpResponse& response) {
  if (response.json_body().empty()) {
    LOG(ERROR) << "No datapath found in the AddEgressResponse.";
    return parsing_status_ = absl::InvalidArgumentError(
               "No datapath found in the AddEgressResponse.");
  }

  auto json_obj = utils::StringToJson(response.json_body());
  if (!json_obj.ok()) {
    parsing_status_ = json_obj.status();
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  parsing_status_ = DecodeJsonBody(*json_obj);
  if (!parsing_status_.ok()) {
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }
  return parsing_status_ = absl::OkStatus();
}

absl::Status AddEgressResponse::DecodeJsonBody(nlohmann::json json_obj) {
  if (!json_obj.is_object()) {
    return absl::InvalidArgumentError("JSON body was not a JSON object.");
  }
  if (json_obj.contains(JsonKeys::kPpnDataplane)) {
    PPN_ASSIGN_OR_RETURN(
        ppn_dataplane_response_,
        ParsePpnDataplaneResponse(json_obj[JsonKeys::kPpnDataplane]));
    return absl::OkStatus();
  }
  if (json_obj.contains(JsonKeys::kIkeDataplane)) {
    PPN_ASSIGN_OR_RETURN(ike_response_,
                         ParseIkeResponse(json_obj[JsonKeys::kIkeDataplane]));
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError(
      "No PPN dataplane found in the AddEgressResponse.");
}

}  // namespace krypton
}  // namespace privacy
