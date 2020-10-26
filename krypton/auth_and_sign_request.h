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

#ifndef PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_
#define PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_

#include <string>

#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/http_request_json.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

// Requesting public key from the Zinc server.
class PublicKeyRequest {
 public:
  PublicKeyRequest() = default;
  ~PublicKeyRequest() = default;
  // Returns the corresponding headers and json_body separately.
  absl::optional<HttpRequestJson> EncodeToJsonObject() const;

 private:
  HttpRequest http_request_;
};

// A class for constructing http AuthAndSignRequest to Zinc.
class AuthAndSignRequest {
 public:
  AuthAndSignRequest(absl::string_view auth_token,
                     absl::string_view service_type,
                     absl::string_view selected_session_manager_ip,
                     absl::optional<std::string> blinded_token,
                     absl::optional<std::string> public_key_hash);
  ~AuthAndSignRequest() = default;

  // Returns the corresponding headers and json_body separately.
  absl::optional<HttpRequestJson> EncodeToJsonObject() const;

 private:
  HttpRequest http_request_;
  Json::Value BuildJson() const;
  const std::string auth_token_;
  const std::string service_type_;
  const std::string selected_session_manager_ip_;
  absl::optional<std::string> blinded_token_;
  absl::optional<std::string> public_key_hash_;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_
