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

#include "privacy/net/krypton/json_keys.h"

namespace privacy {
namespace krypton {

const char JsonKeys::kAuthTokenKey[] = "oauth_token";
const char JsonKeys::kServiceTypeKey[] = "service_type";
const char JsonKeys::kBlindedTokensKey[] = "blinded_token";

// AddEgressRequest
const char JsonKeys::kUnblindedToken[] = "unblinded_token";
const char JsonKeys::kPpn[] = "ppn";
const char JsonKeys::kUnblindedTokenSignature[] = "unblinded_token_signature";
const char JsonKeys::kRegionTokenAndSignature[] = "region_token_and_signature";
const char JsonKeys::kPublicMetadata[] = "public_metadata";
const char JsonKeys::kSigningKeyVersion[] = "signing_key_version";
const char JsonKeys::kMessageMask[] = "message_mask";

// AddEgressResponse
const char JsonKeys::kPpnDataplane[] = "ppn_dataplane";
const char JsonKeys::kIkeDataplane[] = "ike";

// PpnDataplaneRequest
const char JsonKeys::kClientPublicValue[] = "client_public_value";
const char JsonKeys::kClientNonce[] = "client_nonce";
const char JsonKeys::kRekeyVerificationKey[] = "rekey_verification_key";
const char JsonKeys::kSignature[] = "rekey_signature";
const char JsonKeys::kDownlinkSpi[] = "downlink_spi";
const char JsonKeys::kPreviousUplinkSpi[] = "previous_uplink_spi";
const char JsonKeys::kControlPlaneSockAddr[] = "control_plane_sock_addr";
const char JsonKeys::kDataplaneProtocol[] = "dataplane_protocol";
const char JsonKeys::kSuite[] = "suite";
const char JsonKeys::kApnType[] = "apn_type";
const char JsonKeys::kDynamicMtuEnabled[] = "dynamic_mtu_enabled";
const char JsonKeys::kPreferOasis[] = "prefer_oasis";
const char JsonKeys::kUseReservedIpPool[] = "use_reserved_ip_pool";
const char JsonKeys::kAuthMethod[] = "auth_method";
const char JsonKeys::kClientIdType[] = "client_id_type";

// PpnDataplaneResponse
const char JsonKeys::kUserPrivateIp[] = "user_private_ip";
const char JsonKeys::kEgressPointSockAddr[] = "egress_point_sock_addr";
const char JsonKeys::kEgressPointPublicValue[] = "egress_point_public_value";
const char JsonKeys::kServerNonce[] = "server_nonce";
const char JsonKeys::kUplinkSpi[] = "uplink_spi";
const char JsonKeys::kExpiry[] = "expiry";
const char JsonKeys::kMssDetectionSockAddr[] = "mss_detection_sock_addr";
const char JsonKeys::kTransportModeServerPort[] = "transport_mode_server_port";
const char JsonKeys::kControlPlaneAddr[] = "control_plane_addr";

// IpRange
const char JsonKeys::kIpv4[] = "ipv4_range";
const char JsonKeys::kIpv6[] = "ipv6_range";

// PPN
const char JsonKeys::kPem[] = "pem";
const char JsonKeys::kBlindedTokenSignature[] = "blinded_token_signature";
const char JsonKeys::kCopperControllerHostname[] = "copper_controller_hostname";
const char JsonKeys::kPublicKeyHash[] = "public_key_hash";

// AuthCertificates
const char JsonKeys::kServerCaCertificate[] = "server_ca_certificate";
const char JsonKeys::kClientCertificate[] = "client_certificate";

// IKE
const char JsonKeys::kClientId[] = "client_id";
const char JsonKeys::kSharedSecret[] = "shared_secret";
const char JsonKeys::kServerAddress[] = "server_address";
const char JsonKeys::kCertificates[] = "certificates";

// Attestation
const char JsonKeys::kAttestationNonce[] = "attestation_nonce";

// UpdatePathInfoRequest
const char JsonKeys::kSessionId[] = "session_id";
const char JsonKeys::kUplinkMtu[] = "uplink_mtu";
const char JsonKeys::kDownlinkMtu[] = "downlink_mtu";
const char JsonKeys::kMtuUpdateSignature[] = "mtu_update_signature";

// PublicMetadata
const char JsonKeys::kExitLocation[] = "exit_location";
const char JsonKeys::kServiceType[] = "service_type";
const char JsonKeys::kExpiration[] = "expiration";
const char JsonKeys::kDebugMode[] = "debug_mode";

// Location
const char JsonKeys::kCountry[] = "country";
const char JsonKeys::kCityGeoId[] = "city_geo_id";

// Timestamp
const char JsonKeys::kSeconds[] = "seconds";
const char JsonKeys::kNanos[] = "nanos";

}  // namespace krypton
}  // namespace privacy
