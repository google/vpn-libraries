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

#include "privacy/net/krypton/auth_and_sign_request.h"

#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

AuthAndSignRequest::AuthAndSignRequest(
    absl::string_view auth_token, absl::string_view service_type,
    absl::string_view selected_session_manager_ip,
    absl::optional<std::string> blinded_token,
    absl::optional<std::string> public_key_hash)
    : auth_token_(auth_token),
      service_type_(service_type),
      selected_session_manager_ip_(selected_session_manager_ip),
      blinded_token_(blinded_token),
      public_key_hash_(public_key_hash) {}

absl::optional<HttpRequest> AuthAndSignRequest::EncodeToProto() const {
  HttpRequest http_request;
  http_request.set_json_body(BuildBody());
  return http_request;
}

std::string AuthAndSignRequest::BuildBody() const {
  Json::FastWriter writer;
  return writer.write(BuildBodyJson());
}

Json::Value AuthAndSignRequest::BuildBodyJson() const {
  Json::Value json_body;
  json_body[JsonKeys::kAuthTokenKey] = auth_token_;
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

absl::optional<HttpRequest> PublicKeyRequest::EncodeToProto() const {
  HttpRequest request;

  // TODO: We don't need to send this parameter after the GET
  // request is implemented.
  Json::Value json_body;
  json_body["get_public_key"] = true;

  Json::FastWriter writer;
  request.set_json_body(writer.write(json_body));
  return request;
}

}  // namespace krypton
}  // namespace privacy
