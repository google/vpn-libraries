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

#include "privacy/net/krypton/add_egress_request.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <memory>
#include <optional>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace {
constexpr int kCopperPort = 1849;

void AddJwtTokenAsUnblindedToken(
    Json::Value& json_body,
    std::shared_ptr<AuthAndSignResponse> auth_response) {
  if (auth_response->blinded_token_signatures().empty()) {
    LOG(INFO) << "Using JWT token as there are no blinded tokens";
    json_body[JsonKeys::kUnblindedToken] = auth_response->jwt_token();
    return;
  }
}
}  // namespace

// Returns the corresponding headers and json_body separately.
absl::optional<HttpRequest> AddEgressRequest::EncodeToProtoForBridge(
    std::shared_ptr<AuthAndSignResponse> auth_response) {
  HttpRequest request;
  Json::FastWriter writer;
  request.set_json_body(writer.write(BuildBodyJson(std::move(auth_response))));
  return request;
}

absl::optional<HttpRequest> AddEgressRequest::EncodeToProtoForPpn(
    const PpnDataplaneRequestParams& params) {
  HttpRequest request;
  Json::FastWriter writer;
  request.set_json_body(writer.write(BuildBodyJson(params)));
  return request;
}

Json::Value AddEgressRequest::BuildBodyJson(
    std::shared_ptr<AuthAndSignResponse> auth_response) {
  Json::Value json_body;
  AddJwtTokenAsUnblindedToken(json_body, auth_response);

  Json::Value bridge;
  bridge[JsonKeys::kOperation] = "SESSION_START";

  return json_body;
}

Json::Value AddEgressRequest::BuildBodyJson(
    const PpnDataplaneRequestParams& params) {
  Json::Value json_body;
  Json::Value ppn;

  // Add blind stuff.
  if (!params.blind_token_enabled) {
    AddJwtTokenAsUnblindedToken(json_body, params.auth_response);
  } else {
    json_body[JsonKeys::kIsUnblindedToken] = true;
    json_body[JsonKeys::kUnblindedToken] = params.blind_message;
    json_body[JsonKeys::kUnblindedTokenSignature] =
        params.unblinded_token_signature;
  }

  json_body[JsonKeys::kRegionTokenAndSignature] =
      params.region_token_and_signature;

  auto my_keys = params.crypto->GetMyKeyMaterial();
  ppn[JsonKeys::kClientPublicValue] = my_keys.public_value;
  ppn[JsonKeys::kClientNonce] = my_keys.nonce;
  ppn[JsonKeys::kDownlinkSpi] = params.crypto->downlink_spi();
  ppn[JsonKeys::kApnType] = params.apn_type;
  ppn[JsonKeys::kDataplaneProtocol] =
      KryptonConfig::DatapathProtocol_Name(params.dataplane_protocol);
  ppn[JsonKeys::kSuite] =
      ppn::PpnDataplaneRequest::CryptoSuite_Name(params.suite);

  auto ip_range = utils::IPRange::Parse(params.copper_control_plane_address);
  if (ip_range.status().ok()) {
    ppn[JsonKeys::kControlPlaneSockAddr] =
        ip_range->HostPortString(kCopperPort);
  }

  if (params.crypto->GetRekeyVerificationKey().ok()) {
    ppn[JsonKeys::kRekeyVerificationKey] =
        params.crypto->GetRekeyVerificationKey().value();
  }
  if (params.is_rekey) {
    ppn[JsonKeys::kSignature] = params.signature;
    ppn[JsonKeys::kPreviousUplinkSpi] = params.uplink_spi;
  }

  json_body[JsonKeys::kPpn] = ppn;

  return json_body;
}

}  // namespace krypton
}  // namespace privacy
