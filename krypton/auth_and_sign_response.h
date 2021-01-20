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

#ifndef PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_
#define PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_

#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

class PublicKeyResponse {
 public:
  PublicKeyResponse() = default;
  ~PublicKeyResponse() = default;

  // Decodes the proto to AuthAndSignResponse.
  absl::Status DecodeFromProto(const HttpResponse& response);

  absl::Status parsing_status() const { return parsing_status_; }
  const std::string& pem() const { return pem_; }

 private:
  std::string pem_;
  absl::Status DecodeJsonBody(Json::Value value);
  absl::Status parsing_status_ = absl::InternalError("Not initialized");
};

// Response for the Auth.
class AuthAndSignResponse {
 public:
  AuthAndSignResponse() = default;
  ~AuthAndSignResponse() = default;

  // Decodes the proto to AuthAndSignResponse.
  absl::Status DecodeFromProto(const HttpResponse& response);

  absl::Status parsing_status() const { return parsing_status_; }
  const std::string& jwt_token() const { return jwt_token_; }
  const std::vector<std::string>& blinded_token_signatures() const {
    return blinded_token_signatures_;
  }

 private:
  // Decode Auth specific parameters
  absl::Status DecodeJsonBody(Json::Value value);
  std::string jwt_token_;
  std::vector<std::string> blinded_token_signatures_;
  std::vector<std::string> session_manager_ips_;
  absl::Status parsing_status_ = absl::InternalError("Not initialized");
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_
