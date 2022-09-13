
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

#include "privacy/net/krypton/auth_and_sign_response.h"

#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/zinc/rpc/zinc.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

absl::Status AuthAndSignResponse::DecodeFromProto(const HttpResponse& response,
                                                  const KryptonConfig& config) {
  if (response.has_proto_body()) {
    parsing_status_ = DecodeProtoBody(response.proto_body(), config);
    if (!parsing_status_.ok()) {
      LOG(ERROR) << "Unable to parse proto body: " << parsing_status_;
      return parsing_status_;
    }
    return absl::OkStatus();
  }

  if (response.json_body().empty()) {
    return parsing_status_ = absl::InvalidArgumentError("missing json body");
  }

  Json::Reader reader;
  Json::Value body_root;
  auto parsing_status = reader.parse(response.json_body(), body_root);
  if (!parsing_status) {
    parsing_status_ = absl::InvalidArgumentError("Error parsing json body");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  parsing_status_ = DecodeJsonBody(body_root, config);
  if (!parsing_status_.ok()) {
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  return parsing_status_ = absl::OkStatus();
}

absl::Status AuthAndSignResponse::DecodeProtoBody(absl::string_view bytes,
                                                  const KryptonConfig& config) {
  ppn::AuthAndSignResponse response;
  if (!response.ParseFromString(bytes)) {
    return absl::InvalidArgumentError("Cannot parse response proto");
  }

  blinded_token_signatures_.clear();
  for (const auto& signature : response.blinded_token_signature()) {
    blinded_token_signatures_.push_back(signature);
  }

  const std::string hostname = response.copper_controller_hostname();
  if (!hostname.empty()) {
    bool matched = false;
    // If zinc provides a hostname,
    // we check whether it fits any suffix in the copper_hostname_suffix list;
    // there's no empty suffix in the copper_hostname_suffix list.
    for (const auto& suffix : config.copper_hostname_suffix()) {
      if (absl::EndsWith(hostname, suffix)) {
        copper_controller_hostname_ = hostname;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // TODO: investigate making AuthAndSignResponse reusable.
      return absl::InvalidArgumentError(absl::StrCat(
          "copper_controller_hostname doesn't have allowed suffix: ",
          hostname));
    }
  }

  region_token_and_signatures_ = response.region_token_and_signature();

  apn_type_ = response.apn_type();
  if (!apn_type_.empty()) {
    if (apn_type_ != "ppn" && apn_type_ != "bridge") {
      return absl::InvalidArgumentError("unexpected apn_type");
    }
  }

  return absl::OkStatus();
}

absl::Status AuthAndSignResponse::DecodeJsonBody(Json::Value value,
                                                 const KryptonConfig& config) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body is not of type JSON object");
  }

  if (value.isMember("jwt")) {
    return absl::InvalidArgumentError("jwt response is not supported");
  }

  // TODO: Consider whether to reject any response that doesn't contain
  // blind token signatures.

  blinded_token_signatures_.clear();
  if (value.isMember(JsonKeys::kBlindedTokenSignature)) {
    auto signature_array = value[JsonKeys::kBlindedTokenSignature];
    if (!signature_array.isArray()) {
      return absl::InvalidArgumentError(
          "blinded_token_signature is not an array");
    }
    for (const auto& i : signature_array) {
      if (i.isString()) {
        blinded_token_signatures_.push_back(i.asString());
      } else {
        return absl::InvalidArgumentError(
            "blinded_token_signature value is not a string");
      }
    }
  }

  if (value.isMember(JsonKeys::kCopperControllerHostname)) {
    auto hostname_string = value[JsonKeys::kCopperControllerHostname];
    if (!hostname_string.isString()) {
      return absl::InvalidArgumentError(
          "copper_controller_hostname is not a string");
    }
    const std::string hostname = hostname_string.asString();
    if (!hostname.empty()) {
      bool matched = false;
      // If zinc provides a hostname,
      // we check whether it fits any suffix in the copper_hostname_suffix list;
      // there's no empty suffix in the copper_hostname_suffix list.
      for (const auto& suffix : config.copper_hostname_suffix()) {
        if (absl::EndsWith(hostname, suffix)) {
          copper_controller_hostname_ = hostname;
          matched = true;
          break;
        }
      }
      if (!matched) {
        // TODO: investigate making AuthAndSignResponse reusable.
        return absl::InvalidArgumentError(absl::StrCat(
            "copper_controller_hostname doesn't have allowed suffix: ",
            hostname));
      }
    }
  }

  if (value.isMember(JsonKeys::kRegionTokenAndSignature)) {
    auto region_token_and_sig = value[JsonKeys::kRegionTokenAndSignature];
    if (!region_token_and_sig.isString()) {
      return absl::InvalidArgumentError("region_token_and_sig is not a string");
    }
    region_token_and_signatures_ = region_token_and_sig.asString();
  }

  if (value.isMember(JsonKeys::kApnType)) {
    const auto apn_type = value[JsonKeys::kApnType];
    if (!apn_type.isString()) {
      return absl::InvalidArgumentError("apn_type is not a string");
    }
    const std::string type = apn_type.asString();
    if (type != "ppn" && type != "bridge") {
      return absl::InvalidArgumentError("unexpected apn_type");
    }
    apn_type_ = type;
  }
  return absl::OkStatus();
}

absl::Status PublicKeyResponse::DecodeFromProto(const HttpResponse& response) {
  if (response.json_body().empty()) {
    parsing_status_ = absl::InvalidArgumentError("response missing json body");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  // Try to parse the JSON in the body.
  Json::Reader reader;
  Json::Value body_root;
  auto parsing_status = reader.parse(response.json_body(), body_root);
  if (!parsing_status) {
    parsing_status_ = absl::InvalidArgumentError("error parsing json body");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  PPN_RETURN_IF_ERROR(parsing_status_ = DecodeJsonBody(body_root));

  return parsing_status_ = absl::OkStatus();
}

absl::Status PublicKeyResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body is not a JSON object");
  }
  if (!value.isMember(JsonKeys::kPem)) {
    return absl::InvalidArgumentError("missing pem");
  }
  if (!value[JsonKeys::kPem].isString()) {
    return absl::InvalidArgumentError("pem is not a string");
  }
  pem_ = value[JsonKeys::kPem].asString();
  if (value.isMember(JsonKeys::kAttestationNonce)) {
    if (!value[JsonKeys::kAttestationNonce].isString()) {
      return absl::InvalidArgumentError("nonce is not a string");
    }
    nonce_ = value[JsonKeys::kAttestationNonce].asString();
  }
  return absl::OkStatus();
}

}  // namespace krypton
}  // namespace privacy
