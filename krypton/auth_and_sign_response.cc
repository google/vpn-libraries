
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

#include <string>
#include <vector>

#include "base/logging.h"
#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

absl::Status AuthAndSignResponse::DecodeFromProto(
    const HttpResponse& response, const KryptonConfig& config,
    const bool enforce_copper_suffix) {
  if (response.has_proto_body()) {
    parsing_status_ =
        DecodeProtoBody(response.proto_body(), config, enforce_copper_suffix);
    if (!parsing_status_.ok()) {
      LOG(ERROR) << "Unable to parse proto body: " << parsing_status_;
      return parsing_status_;
    }
    return absl::OkStatus();
  }

  if (response.json_body().empty()) {
    return parsing_status_ = absl::InvalidArgumentError("missing json body");
  }

  auto body_root = utils::StringToJson(response.json_body());
  if (!body_root.ok()) {
    parsing_status_ = absl::InvalidArgumentError("Error parsing json body");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  parsing_status_ = DecodeJsonBody(*body_root, config, enforce_copper_suffix);
  if (!parsing_status_.ok()) {
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  return parsing_status_ = absl::OkStatus();
}

absl::Status AuthAndSignResponse::SetCopperHostname(
    absl::string_view hostname, const KryptonConfig& config,
    const bool enforce_copper_suffix) {
  if (hostname.empty()) {
    return absl::OkStatus();
  }
  if (enforce_copper_suffix) {
    bool matched = false;
    // If zinc provides a hostname,
    // we check whether it fits any suffix in the copper_hostname_suffix list;
    // there's no empty suffix in the copper_hostname_suffix list.
    for (const auto& suffix : config.copper_hostname_suffix()) {
      if (absl::EndsWith(hostname, suffix)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return absl::InvalidArgumentError(absl::StrCat(
          "copper_controller_hostname doesn't have allowed suffix: ",
          hostname));
    }
  }
  copper_controller_hostname_ = hostname;
  return absl::OkStatus();
}

absl::Status AuthAndSignResponse::DecodeProtoBody(
    absl::string_view bytes, const KryptonConfig& config,
    const bool enforce_copper_suffix) {
  ppn::AuthAndSignResponse response;
  if (!response.ParseFromString(bytes)) {
    return absl::InvalidArgumentError("Cannot parse response proto");
  }

  blinded_token_signatures_.clear();
  for (const auto& signature : response.blinded_token_signature()) {
    blinded_token_signatures_.push_back(signature);
  }

  region_token_and_signatures_ = response.region_token_and_signature();

  apn_type_ = response.apn_type();
  if (!apn_type_.empty()) {
    if (apn_type_ != "ppn" && apn_type_ != "bridge") {
      return absl::InvalidArgumentError("unexpected apn_type");
    }
  }

  const std::string& hostname = response.copper_controller_hostname();
  return SetCopperHostname(hostname, config, enforce_copper_suffix);
}

absl::Status AuthAndSignResponse::DecodeJsonBody(
    nlohmann::json value, const KryptonConfig& config,
    const bool enforce_copper_suffix) {
  if (!value.is_object()) {
    return absl::InvalidArgumentError("JSON body is not of type JSON object");
  }

  if (value.contains("jwt")) {
    return absl::InvalidArgumentError("jwt response is not supported");
  }

  // TODO: Consider whether to reject any response that doesn't contain
  // blind token signatures.

  blinded_token_signatures_.clear();
  PPN_ASSIGN_OR_RETURN(
      std::optional<std::vector<std::string>> blinded_token_signatures,
      utils::JsonGetStringArray(value, JsonKeys::kBlindedTokenSignature));
  if (blinded_token_signatures) {
    blinded_token_signatures_ = *blinded_token_signatures;
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::string> region_token_and_signature,
      utils::JsonGetString(value, JsonKeys::kRegionTokenAndSignature));
  if (region_token_and_signature) {
    region_token_and_signatures_ = *region_token_and_signature;
  }

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> apn_type,
                       utils::JsonGetString(value, JsonKeys::kApnType));
  if (apn_type) {
    if (*apn_type != "ppn" && *apn_type != "bridge") {
      return absl::InvalidArgumentError("unexpected apn_type");
    }
    apn_type_ = *apn_type;
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::string> copper_controller_hostname,
      utils::JsonGetString(value, JsonKeys::kCopperControllerHostname));
  if (copper_controller_hostname) {
    PPN_RETURN_IF_ERROR(SetCopperHostname(*copper_controller_hostname, config,
                                          enforce_copper_suffix));
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
  auto body_root = utils::StringToJson(response.json_body());
  if (!body_root.ok()) {
    parsing_status_ = absl::InvalidArgumentError("Error parsing json body");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  PPN_RETURN_IF_ERROR(parsing_status_ = DecodeJsonBody(*body_root));

  return parsing_status_ = absl::OkStatus();
}

absl::Status PublicKeyResponse::DecodeJsonBody(nlohmann::json value) {
  if (!value.is_object()) {
    return absl::InvalidArgumentError("JSON body is not a JSON object");
  }

  PPN_ASSIGN_OR_RETURN(std::optional<std::string> pem,
                       utils::JsonGetString(value, JsonKeys::kPem));
  if (pem) {
    pem_ = *pem;
  } else {
    return absl::InvalidArgumentError("missing pem");
  }

  PPN_ASSIGN_OR_RETURN(
      std::optional<std::string> nonce,
      utils::JsonGetString(value, JsonKeys::kAttestationNonce));
  if (nonce) {
    nonce_ = *nonce;
  }
  return absl::OkStatus();
}

absl::StatusOr<ppn::GetInitialDataResponse> DecodeGetInitialDataResponse(
    const HttpResponse& response) {
  ppn::GetInitialDataResponse initial_data_response;
  if (response.has_json_body()) {
    return absl::InvalidArgumentError(
        "Unable to process HttpResponse.json_body()");
  }

  if (response.has_proto_body()) {
    if (!initial_data_response.ParseFromString(response.proto_body())) {
      return absl::InvalidArgumentError("Error parsing proto_body");
    }
  } else {
    return absl::InvalidArgumentError("HttpResponse is missing proto_body");
  }
  return initial_data_response;
}

}  // namespace krypton
}  // namespace privacy
