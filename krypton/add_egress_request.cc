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

#include "privacy/net/krypton/add_egress_request.h"

#include <optional>
#include <string>

#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/time/time.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {

HttpRequest AddEgressRequest::EncodeToProtoForPpn(
    const PpnDataplaneRequestParams& params) {
  HttpRequest request;
  request.set_json_body(utils::JsonToString(BuildBodyJson(params)));
  if (api_key_) {
    (*request.mutable_headers())["X-Goog-Api-Key"] = api_key_.value();
  }
  return request;
}

nlohmann::json AddEgressRequest::BuildBodyJson(
    const PpnDataplaneRequestParams& params) {
  nlohmann::json json_body;
  nlohmann::json ppn;

  if (request_destination_ == RequestDestination::kBeryllium) {
    nlohmann::json exit_location;
    nlohmann::json expiration;
    nlohmann::json public_metadata;

    exit_location[JsonKeys::kCountry] = params.country;
    exit_location[JsonKeys::kCityGeoId] = params.city_geo_id;

    auto time = absl::ToTimespec(params.expiration);
    expiration[JsonKeys::kSeconds] = time.tv_sec;
    expiration[JsonKeys::kNanos] = time.tv_nsec;

    public_metadata[JsonKeys::kExitLocation] = exit_location;
    public_metadata[JsonKeys::kServiceType] = params.service_type;
    public_metadata[JsonKeys::kExpiration] = expiration;
    public_metadata[JsonKeys::kDebugMode] = params.debug_mode;

    json_body[JsonKeys::kPublicMetadata] = public_metadata;
    json_body[JsonKeys::kSigningKeyVersion] = params.signing_key_version;
    json_body[JsonKeys::kMessageMask] = params.message_mask;
    json_body[JsonKeys::kUnblindedToken] = params.unblinded_token;
  }

  if (request_destination_ == RequestDestination::kBrass) {
    json_body[JsonKeys::kUnblindedToken] = params.blind_message;
  }
  json_body[JsonKeys::kUnblindedTokenSignature] =
      params.unblinded_token_signature;

  json_body[JsonKeys::kRegionTokenAndSignature] =
      params.region_token_and_signature;

  auto my_keys = params.crypto->GetMyKeyMaterial();
  std::string public_value_encoded;
  std::string nonce_encoded;
  absl::Base64Escape(my_keys.public_value, &public_value_encoded);
  absl::Base64Escape(my_keys.nonce, &nonce_encoded);

  ppn[JsonKeys::kClientPublicValue] = public_value_encoded;
  ppn[JsonKeys::kClientNonce] = nonce_encoded;
  ppn[JsonKeys::kDownlinkSpi] = params.crypto->downlink_spi();
  ppn[JsonKeys::kApnType] = params.apn_type;

  if (params.dynamic_mtu_enabled) {
    ppn[JsonKeys::kDynamicMtuEnabled] = params.dynamic_mtu_enabled;
  }
  ppn[JsonKeys::kDataplaneProtocol] =
      KryptonConfig::DatapathProtocol_Name(params.dataplane_protocol);
  ppn[JsonKeys::kSuite] =
      net::common::proto::PpnDataplaneRequest::CryptoSuite_Name(params.suite);

  ppn[JsonKeys::kControlPlaneSockAddr] = params.control_plane_sockaddr;
  ppn[JsonKeys::kPreferOasis] = params.prefer_oasis;
  ppn[JsonKeys::kUseReservedIpPool] = params.use_reserved_ip_pool;

  auto verification_key = params.crypto->GetRekeyVerificationKey();
  if (verification_key.ok()) {
    std::string verification_key_encoded;
    absl::Base64Escape(*verification_key, &verification_key_encoded);

    ppn[JsonKeys::kRekeyVerificationKey] = verification_key_encoded;
  }
  if (params.is_rekey) {
    std::string signature_encoded;
    absl::Base64Escape(params.signature, &signature_encoded);

    ppn[JsonKeys::kSignature] = signature_encoded;
    ppn[JsonKeys::kPreviousUplinkSpi] = params.uplink_spi;
  }

  json_body[JsonKeys::kPpn] = ppn;
  return json_body;
}

}  // namespace krypton
}  // namespace privacy
