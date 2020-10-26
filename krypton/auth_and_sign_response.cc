
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

#include "privacy/net/krypton/auth_and_sign_response.h"

#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

absl::Status AuthAndSignResponse::DecodeFromJsonObject(
    absl::string_view json_string) {
  Json::Reader reader;
  Json::Value root;
  auto parsing_status = reader.parse(std::string(json_string), root);
  if (!parsing_status) {
    parsing_status_ = absl::InvalidArgumentError("Error parsing HttpResponse");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }

  for (auto it = root.begin(); it != root.end(); ++it) {
    Json::FastWriter writer;
    if (it.name() == JsonKeys::kStatusKey) {
      auto status = http_response_.DecodeFromJsonObject(*it);
      if (!status.ok()) {
        parsing_status_ = absl::InvalidArgumentError(
            "Error parsing HttpResponse with status ");
        LOG(ERROR) << parsing_status_;
        return parsing_status_;
      }
    } else if (it.name() == JsonKeys::kHeadersKey) {
      auto status = http_response_.MutableHeader()->DecodeFromJsonObject(*it);
      if (!status.ok()) {
        parsing_status_ =
            absl::InvalidArgumentError("Error parsing HttpResponse header");
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

absl::Status AuthAndSignResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body was not a JSON object.");
  }
  if (value.isMember(JsonKeys::kJwtTokenKey)) {
    jwt_token_ = value[JsonKeys::kJwtTokenKey].asString();
  }

  if (value.isMember(JsonKeys::kBlindedTokenSignature)) {
    auto signature_array = value[JsonKeys::kBlindedTokenSignature];
    if (!signature_array.isArray()) {
      return absl::InvalidArgumentError("BlindedTokens is not of type Array");
    }
    for (const auto& i : signature_array) {
      if (i.isString()) {
        blinded_token_signatures_.push_back(i.asString());
      } else {
        LOG(ERROR)
            << "Received blind_token_signature that is not of type string";
      }
    }
  }

  return absl::OkStatus();
}

absl::Status PublicKeyResponse::DecodeFromJsonObject(
    absl::string_view json_string) {
  Json::Reader reader;
  Json::Value root;
  auto parsing_status = reader.parse(std::string(json_string), root);
  if (!parsing_status) {
    parsing_status_ = absl::InvalidArgumentError("Error parsing HttpResponse");
    LOG(ERROR) << parsing_status_;
    return parsing_status_;
  }
  for (auto it = root.begin(); it != root.end(); ++it) {
    Json::FastWriter writer;
    if (it.name() == JsonKeys::kStatusKey) {
      PPN_RETURN_IF_ERROR(http_response_.DecodeFromJsonObject(*it));

      if (!http_response_.is_successful()) {
        parsing_status_ = absl::Status(
            utils::GetStatusCodeForHttpStatus(http_response_.status()),
            "Content obfuscated");
        LOG(ERROR) << parsing_status_;
        return parsing_status_;
      }
    } else if (it.name() == JsonKeys::kHeadersKey) {
      PPN_RETURN_IF_ERROR(
          http_response_.MutableHeader()->DecodeFromJsonObject(*it));
    } else if (it.name() == JsonKeys::kJsonBodyKey) {
      PPN_RETURN_IF_ERROR(DecodeJsonBody(*it));
    }
  }
  return parsing_status_ = absl::OkStatus();
}

absl::Status PublicKeyResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body was not a JSON object.");
  }
  if (!value.isMember(JsonKeys::kPem)) {
    return absl::FailedPreconditionError("No pem field found");
  }
  pem_ = value[JsonKeys::kPem].asString();
  return absl::OkStatus();
}

}  // namespace krypton
}  // namespace privacy
