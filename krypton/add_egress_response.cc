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

#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

using privacy::ppn::PpnDataplaneResponse;
using privacy::ppn::PpnIkeResponse;

namespace {

// Fill proto repeated field containing string values from a json array.
absl::Status CopyStringArray(nlohmann::json object, const std::string& key,
                             ::proto2::RepeatedPtrField<std::string>* output) {
  output->Clear();
  if (!object.contains(key)) {
    // Proto 3 doesn't distinguish between a missing field and an empty field,
    // so if it's missing, we won't count that as an error.
    return absl::OkStatus();
  }
  auto array = object[key];
  if (!array.is_array()) {
    return absl::InvalidArgumentError(
        absl::StrCat(key, " is not of array type"));
  }

  for (const auto& element : array) {
    if (!element.is_string()) {
      return absl::InvalidArgumentError(
          absl::StrCat(key, " element is not of type string"));
    }
    output->Add(element);
  }
  return absl::OkStatus();
}

// Helper macro to copy a string array from json to proto, with error checking.
#define COPY_STRING_ARRAY(json_obj, json_key, proto, proto_field)   \
  PPN_RETURN_IF_ERROR(CopyStringArray(json_obj, JsonKeys::json_key, \
                                      proto.mutable_##proto_field()))

// Helper macros to copy values from json to proto, with error checking.
// Proto 3 doesn't distinguish between a missing field and a default value, so
// if it's missing, leave it as the default value.
#define COPY_SCALAR_VALUE(json_obj, json_key, proto, proto_field, type_check, \
                          type)                                               \
  do {                                                                        \
    if (!json_obj.contains(JsonKeys::json_key)) {                             \
      break;                                                                  \
    }                                                                         \
    if (!json_obj[JsonKeys::json_key].type_check()) {                         \
      return absl::InvalidArgumentError(                                      \
          absl::StrCat(JsonKeys::json_key, " value is incorrect type"));      \
    }                                                                         \
    type value = json_obj[JsonKeys::json_key];                                \
    proto.set_##proto_field(value);                                           \
  } while (0)

#define COPY_INT_VALUE(json_obj, json_key, proto, proto_field)                 \
  COPY_SCALAR_VALUE(json_obj, json_key, proto, proto_field, is_number_integer, \
                    int)

#define COPY_STRING_VALUE(json_obj, json_key, proto, proto_field)      \
  COPY_SCALAR_VALUE(json_obj, json_key, proto, proto_field, is_string, \
                    std::string)

// Similar to COPY_STRING_VALUE, but decodes base64 strings as bytes.
#define COPY_BYTES_VALUE(json_obj, json_key, proto, proto_field)           \
  do {                                                                     \
    if (!json_obj.contains(JsonKeys::json_key)) {                          \
      break;                                                               \
    }                                                                      \
    if (!json_obj[JsonKeys::json_key].is_string()) {                       \
      return absl::InvalidArgumentError(                                   \
          absl::StrCat(JsonKeys::json_key, " value is not a string"));     \
    }                                                                      \
    std::string encoded = json_obj[JsonKeys::json_key];                    \
    std::string decoded;                                                   \
    if (!absl::Base64Unescape(encoded, &decoded)) {                        \
      return absl::InvalidArgumentError(                                   \
          absl::StrCat(JsonKeys::json_key, " value is not valid base64")); \
    }                                                                      \
    proto.set_##proto_field(decoded);                                      \
  } while (0)

absl::StatusOr<PpnDataplaneResponse> ParsePpnDataplaneResponse(
    nlohmann::json json) {
  PpnDataplaneResponse response;

  // We can't use the macros above to copy the user private IPs, because the
  // types in the protos don't example match the JSON.
  if (json.contains(JsonKeys::kUserPrivateIp)) {
    if (!json[JsonKeys::kUserPrivateIp].is_array()) {
      return absl::InvalidArgumentError(
          "user_private_ip field was not an array");
    }

    for (const auto& private_ip : json[JsonKeys::kUserPrivateIp]) {
      if (private_ip.contains(JsonKeys::kIpv4)) {
        std::string value = private_ip[JsonKeys::kIpv4];
        response.add_user_private_ip()->set_ipv4_range(value);
      }
      if (private_ip.contains(JsonKeys::kIpv6)) {
        std::string value = private_ip[JsonKeys::kIpv6];
        response.add_user_private_ip()->set_ipv6_range(value);
      }
    }
  }

  COPY_STRING_ARRAY(json, kEgressPointSockAddr, response,
                    egress_point_sock_addr);

  // Technically, we're storing the base64 encoded values instead of the bytes
  // themselves, and then we pass the base64 on the wire back to the backend.
  // That's fine for now, and saves us from decoding and encoding. But if we
  // switch to using binary protos instead of JSON, we'll need to make sure we
  // treat these fields consistently.
  COPY_STRING_VALUE(json, kEgressPointPublicValue, response,
                    egress_point_public_value);
  COPY_STRING_VALUE(json, kServerNonce, response, server_nonce);

  COPY_INT_VALUE(json, kUplinkSpi, response, uplink_spi);

  COPY_STRING_ARRAY(json, kMssDetectionSockAddr, response,
                    mss_detection_sock_addr);

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

  COPY_BYTES_VALUE(json, kClientId, response, client_id);
  COPY_BYTES_VALUE(json, kSharedSecret, response, shared_secret);

  COPY_STRING_VALUE(json, kServerAddress, response, server_address);

  return response;
}

#undef COPY_STRING_VALUE
#undef COPY_INT_VALUE
#undef COPY_SCALAR_VALUE
#undef COPY_STRING_ARRAY
#undef COPY_BYTES_VALUE

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
