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
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
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

using privacy::ppn::PpnDataplaneResponse;

namespace {

// Fill proto repeated field containing string values from a json array.
absl::Status CopyStringArray(Json::Value object, const std::string& key,
                             ::proto2::RepeatedPtrField<std::string>* output) {
  output->Clear();
  if (!object.isMember(key)) {
    // Proto 3 doesn't distinguish between a missing field and an empty field,
    // so if it's missing, we won't count that as an error.
    return absl::OkStatus();
  }
  auto array = object[key];
  if (!array.isArray()) {
    return absl::InvalidArgumentError(
        absl::StrCat(key, " is not of array type"));
  }

  for (const auto& element : array) {
    if (!element.isString()) {
      return absl::InvalidArgumentError(
          absl::StrCat(key, " element is not of type string"));
    }
    output->Add(element.asString());
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
                          type_cast)                                          \
  do {                                                                        \
    if (!json_obj.isMember(JsonKeys::json_key)) {                             \
      break;                                                                  \
    }                                                                         \
    if (!json_obj[JsonKeys::json_key].type_check()) {                         \
      return absl::InvalidArgumentError(                                      \
          absl::StrCat(JsonKeys::json_key, " value is incorrect type"));      \
    }                                                                         \
    proto.set_##proto_field(json_obj[JsonKeys::json_key].type_cast());        \
  } while (0)

#define COPY_INT_VALUE(json_obj, json_key, proto, proto_field) \
  COPY_SCALAR_VALUE(json_obj, json_key, proto, proto_field, isIntegral, asInt)

#define COPY_STRING_VALUE(json_obj, json_key, proto, proto_field) \
  COPY_SCALAR_VALUE(json_obj, json_key, proto, proto_field, isString, asString)

absl::StatusOr<PpnDataplaneResponse> ParsePpnDataplaneResponse(
    Json::Value json) {
  PpnDataplaneResponse response;

  // We can't use the macros above to copy the user private IPs, because the
  // types in the protos don't example match the JSON.
  if (json.isMember(JsonKeys::kUserPrivateIp)) {
    if (!json[JsonKeys::kUserPrivateIp].isArray()) {
      return absl::InvalidArgumentError(
          "user_private_ip field was not an array");
    }

    for (const auto& private_ip : json[JsonKeys::kUserPrivateIp]) {
      if (private_ip.isMember(JsonKeys::kIpv4)) {
        response.add_user_private_ip()->set_ipv4_range(
            private_ip[JsonKeys::kIpv4].asString());
      }
      if (private_ip.isMember(JsonKeys::kIpv6)) {
        response.add_user_private_ip()->set_ipv6_range(
            private_ip[JsonKeys::kIpv6].asString());
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

  // This is the only Timestamp value, so there's no need for a helper macro.
  if (json.isMember(JsonKeys::kExpiry)) {
    if (!json[JsonKeys::kExpiry].isString()) {
      return absl::InvalidArgumentError("expiry timestamp is not a string");
    }
    PPN_ASSIGN_OR_RETURN(
        auto expiry, utils::ParseTimestamp(json[JsonKeys::kExpiry].asString()));

    PPN_RETURN_IF_ERROR(utils::ToProtoTime(expiry, response.mutable_expiry()));
  }

  return response;
}

#undef COPY_STRING_VALUE
#undef COPY_INT_VALUE
#undef COPY_SCALAR_VALUE
#undef COPY_STRING_ARRAY

}  // namespace

absl::Status AddEgressResponse::DecodeFromProto(const HttpResponse& response) {
  if (response.json_body().empty()) {
    LOG(ERROR) << "No datapath found in the AddEgressResponse.";
    return parsing_status_ = absl::InvalidArgumentError(
               "No datapath found in the AddEgressResponse.");
  }

  Json::Reader reader;
  Json::Value body_root;
  auto parsing_status = reader.parse(response.json_body(), body_root);
  if (!parsing_status) {
    parsing_status_ = absl::FailedPreconditionError(
        "Cannot parse AddEgressResponse response");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  parsing_status_ = DecodeJsonBody(body_root);
  if (!parsing_status_.ok()) {
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }
  return parsing_status_ = absl::OkStatus();
}

absl::Status AddEgressResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body was not a JSON object.");
  }
  if (value.isMember(JsonKeys::kPpnDataplane)) {
    PPN_ASSIGN_OR_RETURN(
        auto proto, ParsePpnDataplaneResponse(value[JsonKeys::kPpnDataplane]));
    ppn_dataplane_response_ = absl::make_unique<PpnDataplaneResponse>(proto);
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError(
      "No PPN dataplane found in the AddEgressResponse.");
}

}  // namespace krypton
}  // namespace privacy
