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

#ifndef PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_
#define PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_

#include <cstdint>
#include <optional>
#include <string>

#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {

// Requesting public key from the Zinc server.
class PublicKeyRequest {
 public:
  explicit PublicKeyRequest(bool request_nonce,
                            std::optional<std::string> api_key)
      : request_nonce_(request_nonce), api_key_(api_key) {}
  ~PublicKeyRequest() = default;
  HttpRequest EncodeToProto() const;

 private:
  HttpRequest http_request_;
  const bool request_nonce_;
  std::optional<std::string> api_key_;
};

// Request for GetInitialData from authentication service.
class InitialDataRequest {
 public:
  InitialDataRequest(
      bool use_attestation, absl::string_view service_type,
      ppn::GetInitialDataRequest::LocationGranularity location_granularity,
      int64_t validation_version, absl::string_view auth_token)
      : use_attestation_(use_attestation),
        service_type_(service_type),
        granularity_(location_granularity),
        validation_version_(validation_version),
        auth_token_(auth_token) {}
  ~InitialDataRequest() = default;
  HttpRequest EncodeToProto() const;

 private:
  const bool use_attestation_;
  const std::string service_type_;
  ppn::GetInitialDataRequest::LocationGranularity granularity_;
  const int64_t validation_version_;
  const std::string auth_token_;
};

// A class for constructing http AuthAndSignRequest to Zinc.
class AuthAndSignRequest {
 public:
  AuthAndSignRequest(
      absl::string_view auth_token, absl::string_view service_type,
      absl::string_view selected_session_manager_ip,
      std::optional<std::string> blinded_token,
      std::optional<std::string> public_key_hash,
      std::optional<privacy::ppn::AttestationData> attestation_data,
      bool attach_oauth_as_header);
  ~AuthAndSignRequest() = default;

  HttpRequest EncodeToProto() const;

 private:
  nlohmann::json BuildBodyJson() const;
  ppn::AuthAndSignRequest BuildBodyProto() const;

  const std::string auth_token_;
  const std::string service_type_;
  const std::string selected_session_manager_ip_;
  std::optional<std::string> blinded_token_;
  std::optional<std::string> public_key_hash_;
  std::optional<privacy::ppn::AttestationData> attestation_data_;
  bool attach_oauth_as_header_;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_AUTH_AND_SIGN_REQUEST_H_
