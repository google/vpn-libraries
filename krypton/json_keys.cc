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

#include "privacy/net/krypton/json_keys.h"

namespace privacy {
namespace krypton {
const char JsonKeys::kJsonBodyKey[] = "json_body";
const char JsonKeys::kAuthTokenKey[] = "oauth_token";
const char JsonKeys::kServiceTypeKey[] = "service_type";
const char JsonKeys::kJwtTokenKey[] = "jwt";
const char JsonKeys::kStatusKey[] = "status";
const char JsonKeys::kStatusCodeKey[] = "code";
const char JsonKeys::kMessageKey[] = "message";
const char JsonKeys::kHeadersKey[] = "headers";
const char JsonKeys::kBlindedTokensKey[] = "blinded_token";

// Egress
const char JsonKeys::kUnblindedToken[] = "unblinded_token";
const char JsonKeys::kBridge[] = "bridge";
const char JsonKeys::kOperation[] = "operation";
const char JsonKeys::kControlPlaneSockAddr[] = "control_plane_sock_addr";
const char JsonKeys::kControlPlaneSockAddresses[] = "control_plane_sock_addrs";
const char JsonKeys::kSessionId[] = "session_id";
const char JsonKeys::kSessionToken[] = "session_token";
const char JsonKeys::kClientCryptoKey[] = "client_crypto_key";
const char JsonKeys::kServerCryptoKey[] = "server_crypto_key";
const char JsonKeys::kIpRanges[] = "ip_ranges";
const char JsonKeys::kDataplaneSockAddr[] = "data_plane_sock_addrs";
const char JsonKeys::kError[] = "error";

// PPN
const char JsonKeys::kPpn[] = "ppn";
const char JsonKeys::kPpnDataplane[] = "ppn_dataplane";
const char JsonKeys::kClientPublicValue[] = "client_public_value";
const char JsonKeys::kClientNonce[] = "client_nonce";
const char JsonKeys::kUserPrivateIp[] = "user_private_ip";
const char JsonKeys::kEgressPointSockAddr[] = "egress_point_sock_addr";
const char JsonKeys::kEgressPointPublicValue[] = "egress_point_public_value";
const char JsonKeys::kServerNonce[] = "server_nonce";
const char JsonKeys::kUplinkSpi[] = "uplink_spi";
const char JsonKeys::kDownlinkSpi[] = "downlink_spi";
const char JsonKeys::kExpiry[] = "expiry";
const char JsonKeys::kIpv4[] = "ipv4_range";
const char JsonKeys::kIpv6[] = "ipv6_range";
const char JsonKeys::kDataplaneProtocol[] = "dataplane_protocol";
const char JsonKeys::kSuite[] = "suite";
const char JsonKeys::kSignature[] = "rekey_signature";
const char JsonKeys::kRekeyVerificationKey[] = "rekey_verification_key";
const char JsonKeys::kPreviousUplinkSpi[] = "previous_uplink_spi";
const char JsonKeys::kPem[] = "pem";
const char JsonKeys::kBlindedTokenSignature[] = "blinded_token_signature";
const char JsonKeys::kIsUnblindedToken[] = "is_unblinded_token";
const char JsonKeys::kUnblindedTokenSignature[] = "unblinded_token_signature";
const char JsonKeys::kPublicKeyHash[] = "public_key_hash";
}  // namespace krypton
}  // namespace privacy
