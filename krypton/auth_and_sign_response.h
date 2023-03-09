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

#ifndef PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_
#define PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/zinc/rpc/zinc.proto.h"
// anonymous_tokens.proto will release under https://github.com/google/quiche
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/anonymous_tokens/proto/anonymous_tokens.proto.h"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

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

  std::optional<std::string> nonce() { return nonce_; }

 private:
  std::string pem_;
  std::optional<std::string> nonce_;
  absl::Status DecodeJsonBody(nlohmann::json value);
  absl::Status parsing_status_ = absl::InternalError("Not initialized");
};

absl::StatusOr<ppn::GetInitialDataResponse> DecodeGetInitialDataResponse(
    const HttpResponse& response);

// Response for the Auth.
class AuthAndSignResponse {
 public:
  static absl::StatusOr<AuthAndSignResponse> FromProto(
      const HttpResponse& http_response, const KryptonConfig& config) {
    AuthAndSignResponse response;
    PPN_RETURN_IF_ERROR(response.DecodeFromProto(http_response, config));
    return response;
  }

  AuthAndSignResponse() = default;
  ~AuthAndSignResponse() = default;

  const std::vector<std::string>& blinded_token_signatures() const {
    return blinded_token_signatures_;
  }
  const std::string& copper_controller_hostname() const {
    return copper_controller_hostname_;
  }
  const std::string& region_token_and_signatures() const {
    return region_token_and_signatures_;
  }
  const std::string& apn_type() const { return apn_type_; }

 private:
  // Decodes the proto to AuthAndSignResponse.
  absl::Status DecodeFromProto(const HttpResponse& response,
                               const KryptonConfig& config);

  // Decode Auth specific parameters
  absl::Status DecodeJsonBody(nlohmann::json value,
                              const KryptonConfig& config);

  // Decode from AuthAndSignResponse proto;
  absl::Status DecodeProtoBody(absl::string_view bytes,
                               const KryptonConfig& config);

  std::string copper_controller_hostname_;
  std::string region_token_and_signatures_;
  std::string apn_type_;
  std::vector<std::string> blinded_token_signatures_;
  std::vector<std::string> session_manager_ips_;
  absl::Status parsing_status_ = absl::InternalError("Not initialized");
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_RESPONSE_H_
