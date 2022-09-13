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

#include "google/protobuf/any.proto.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/zinc/rpc/zinc.proto.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

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
    http_request.set_json_body(BuildBody());
  }
  if (attach_oauth_as_header_) {
    (*http_request.mutable_headers())["Authorization"] =
        absl::StrCat("Bearer ", auth_token_);
  }
  return http_request;
}

std::string AuthAndSignRequest::BuildBody() const {
  Json::FastWriter writer;
  return writer.write(BuildBodyJson());
}

Json::Value AuthAndSignRequest::BuildBodyJson() const {
  // We have to manually build the json, because the standard proto->JSON
  // converter doesn't work with protolite protos used in Android.
  Json::Value json_body;
  if (!attach_oauth_as_header_) {
    json_body[JsonKeys::kAuthTokenKey] = auth_token_;
  }
  json_body[JsonKeys::kServiceTypeKey] = service_type_;
  if (blinded_token_) {
    Json::Value blinded_tokens_json_array =
        Json::Value(Json::ValueType::arrayValue);
    blinded_tokens_json_array.append(blinded_token_.value());

    json_body[JsonKeys::kBlindedTokensKey] = blinded_tokens_json_array;
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

std::optional<HttpRequest> PublicKeyRequest::EncodeToProto() const {
  HttpRequest request;

  Json::Value json_body;
  json_body["get_public_key"] = true;
  if (request_nonce_) {
    json_body["request_nonce"] = true;
  }
  Json::FastWriter writer;
  request.set_json_body(writer.write(json_body));
  if (api_key_) {
    (*request.mutable_headers())["X-Goog-Api-Key"] = api_key_.value();
  }
  return request;
}

}  // namespace krypton
}  // namespace privacy
