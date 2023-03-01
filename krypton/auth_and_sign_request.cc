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

#include "privacy/net/krypton/auth_and_sign_request.h"

#include <optional>
#include <string>

#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/zinc/rpc/zinc.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

AuthAndSignRequest::AuthAndSignRequest(
    absl::string_view auth_token, absl::string_view service_type,
    absl::string_view selected_session_manager_ip,
    std::optional<std::string> blinded_token,
    std::optional<std::string> public_key_hash,
    std::optional<privacy::ppn::AttestationData> attestation_data,
    bool attach_oauth_as_header)
    : auth_token_(auth_token),
      service_type_(service_type),
      selected_session_manager_ip_(selected_session_manager_ip),
      blinded_token_(blinded_token),
      public_key_hash_(public_key_hash),
      attestation_data_(attestation_data),
      attach_oauth_as_header_(attach_oauth_as_header) {}

std::optional<HttpRequest> AuthAndSignRequest::EncodeToProto() const {
  HttpRequest http_request;
  // Because attestation_data_ has an Any field with arbitrary types in it, it
  // can't be encoded as JSON using a protolite implementation. So, in that
  // case, we can use the binary serialized proto representation instead.
  if (attestation_data_) {
    http_request.set_proto_body(BuildBodyProto().SerializeAsString());
  } else {
    http_request.set_json_body(utils::JsonToString(BuildBodyJson()));
  }
  if (attach_oauth_as_header_) {
    (*http_request.mutable_headers())["Authorization"] =
        absl::StrCat("Bearer ", auth_token_);
  }
  return http_request;
}

nlohmann::json AuthAndSignRequest::BuildBodyJson() const {
  // We have to manually build the json, because the standard proto->JSON
  // converter doesn't work with protolite protos used in Android.
  nlohmann::json json_body;
  if (!attach_oauth_as_header_) {
    json_body[JsonKeys::kAuthTokenKey] = auth_token_;
  }
  json_body[JsonKeys::kServiceTypeKey] = service_type_;
  if (blinded_token_) {
    json_body[JsonKeys::kBlindedTokensKey] =
        nlohmann::json::array({blinded_token_.value()});
  }
  if (public_key_hash_) {
    json_body[JsonKeys::kPublicKeyHash] = public_key_hash_.value();
  }
  return json_body;
}

ppn::AuthAndSignRequest AuthAndSignRequest::BuildBodyProto() const {
  ppn::AuthAndSignRequest request;
  if (!attach_oauth_as_header_) {
    request.set_oauth_token(auth_token_);
  }
  request.set_service_type(service_type_);
  if (blinded_token_) {
    request.add_blinded_token(*blinded_token_);
  }
  if (public_key_hash_) {
    request.set_public_key_hash(*public_key_hash_);
  }
  if (attestation_data_) {
    *request.mutable_attestation() = *attestation_data_;
  }
  return request;
}

HttpRequest PublicKeyRequest::EncodeToProto() const {
  HttpRequest request;

  nlohmann::json json_obj;
  json_obj["get_public_key"] = true;
  if (request_nonce_) {
    json_obj["request_nonce"] = true;
  }
  request.set_json_body(utils::JsonToString(json_obj));
  if (api_key_) {
    (*request.mutable_headers())["X-Goog-Api-Key"] = api_key_.value();
  }
  return request;
}

HttpRequest InitialDataRequest::EncodeToProto() const {
  HttpRequest http_request;

  ppn::GetInitialDataRequest initial_data_request;
  initial_data_request.set_use_attestation(use_attestation_);
  initial_data_request.set_service_type(service_type_);
  initial_data_request.set_location_granularity(granularity_);
  http_request.set_proto_body(initial_data_request.SerializeAsString());

  (*http_request.mutable_headers())["Authorization"] =
      absl::StrCat("Bearer ", auth_token_);

  (*http_request.mutable_headers())["Content-Type"] = "application/x-protobuf";

  return http_request;
}
}  // namespace krypton
}  // namespace privacy
