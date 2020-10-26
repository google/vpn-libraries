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

#ifndef PRIVACY_NET_KRYPTON_ADD_EGRESS_REQUEST_H_
#define PRIVACY_NET_KRYPTON_ADD_EGRESS_REQUEST_H_

#include <memory>

#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/dataplane_protocol.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/http_request_json.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

// Builds AddEgressRequest to fetch the public keys of the egress nodes.
// Proto definition is brass.proto
class AddEgressRequest {
 public:
  AddEgressRequest() = default;
  ~AddEgressRequest() = default;

  // Parameters needed for PpnDataplane.
  struct PpnDataplaneRequestParams {
   public:
    PpnDataplaneRequestParams() = default;
    ~PpnDataplaneRequestParams() = default;

    std::shared_ptr<AuthAndSignResponse> auth_response;
    const crypto::SessionCrypto* crypto;  // Not owned.
    std::string copper_control_plane_address;
    CryptoSuite suite;
    DataplaneProtocol dataplane_protocol;
    bool is_rekey;
    std::string signature;
    uint32 uplink_spi;
    bool blind_token_enabled = false;
    // Raw text that was sent to Zinc also needs to be sent to Brass.
    std::string blind_message;
    // This is the unblinded signature after receiving the blinding signature
    // from Zinc that needs to be sent to Brass.
    std::string unblinded_token_signature;
  };

  // Returns the corresponding headers and json_body separately.
  absl::optional<HttpRequestJson> EncodeToJsonObjectForBridge(
      std::shared_ptr<AuthAndSignResponse> auth_response);

  absl::optional<HttpRequestJson> EncodeToJsonObjectForPpn(
      const PpnDataplaneRequestParams& params);

 private:
  HttpRequest http_request_;
  Json::Value BuildJson(
      std::shared_ptr<AuthAndSignResponse> auth_response);
  Json::Value BuildJson(const PpnDataplaneRequestParams& params);
};
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_ADD_EGRESS_REQUEST_H_
