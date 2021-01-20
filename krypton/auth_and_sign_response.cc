
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
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
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

absl::Status AuthAndSignResponse::DecodeFromProto(
    const HttpResponse& response) {
  if (!response.json_body().empty()) {
    Json::Reader reader;
    Json::Value body_root;
    auto parsing_status = reader.parse(response.json_body(), body_root);
    if (!parsing_status) {
      parsing_status_ = absl::InvalidArgumentError("Error parsing json body");
      LOG(ERROR) << parsing_status_;
      return parsing_status_;
    }

    parsing_status_ = DecodeJsonBody(body_root);
    if (!parsing_status_.ok()) {
      LOG(ERROR) << parsing_status_;
      return parsing_status_;
    }
  }

  return parsing_status_ = absl::OkStatus();
}

absl::Status AuthAndSignResponse::DecodeJsonBody(Json::Value value) {
  if (!value.isObject()) {
    return absl::InvalidArgumentError("JSON body is not of type JSON object");
  }
  if (value.isMember(JsonKeys::kJwtTokenKey)) {
    jwt_token_ = value[JsonKeys::kJwtTokenKey].asString();
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
  return absl::OkStatus();
}

}  // namespace krypton
}  // namespace privacy
