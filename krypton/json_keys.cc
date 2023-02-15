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

// Egress
const char JsonKeys::kControlPlaneSockAddr[] = "control_plane_sock_addr";
const char JsonKeys::kApnType[] = "apn_type";
const char JsonKeys::kDynamicMtuEnabled[] = "dynamic_mtu_enabled";

// PPN
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
const char JsonKeys::kMssDetectionSockAddr[] = "mss_detection_sock_addr";
const char JsonKeys::kIpv4[] = "ipv4_range";
const char JsonKeys::kIpv6[] = "ipv6_range";
const char JsonKeys::kDataplaneProtocol[] = "dataplane_protocol";
const char JsonKeys::kSuite[] = "suite";
const char JsonKeys::kSignature[] = "rekey_signature";
const char JsonKeys::kRekeyVerificationKey[] = "rekey_verification_key";
const char JsonKeys::kPreviousUplinkSpi[] = "previous_uplink_spi";
const char JsonKeys::kPem[] = "pem";
const char JsonKeys::kBlindedTokenSignature[] = "blinded_token_signature";
const char JsonKeys::kCopperControllerHostname[] = "copper_controller_hostname";
const char JsonKeys::kPublicKeyHash[] = "public_key_hash";

// IKE
const char JsonKeys::kIkeDataplane[] = "ike";
const char JsonKeys::kClientId[] = "client_id";
const char JsonKeys::kSharedSecret[] = "shared_secret";
const char JsonKeys::kServerAddress[] = "server_address";

// Attestation
const char JsonKeys::kAttestationNonce[] = "attestation_nonce";

// UpdatePathInfo
const char JsonKeys::kSessionId[] = "session_id";
const char JsonKeys::kSequenceNumber[] = "sequence_number";
const char JsonKeys::kMtu[] = "mtu";
const char JsonKeys::kVerificationKey[] = "verification_key";
const char JsonKeys::kMtuUpdateSignature[] = "mtu_update_signature";

// AddEgressRequest
const char JsonKeys::kUnblindedToken[] = "unblinded_token";
const char JsonKeys::kPpn[] = "ppn";
const char JsonKeys::kUnblindedTokenSignature[] = "unblinded_token_signature";
const char JsonKeys::kRegionTokenAndSignature[] = "region_token_and_signature";
const char JsonKeys::kSigningKeyVersion[] = "signing_key_version";

// GetInitialDataResponse
const char JsonKeys::kAtPublicMetadataPublicKey[] =
    "at_public_metadata_public_key";
const char JsonKeys::kPublicMetadataInfo[] = "public_metadata_info";
const char JsonKeys::kAttestation[] = "attestation";

// AtPublicMetadataPublicKey
const char JsonKeys::kUseCase[] = "use_case";
const char JsonKeys::kKeyVersion[] = "key_version";
const char JsonKeys::kSerializedPublicKey[] = "serialized_public_key";
const char JsonKeys::kExpirationTime[] = "expiration_time";
const char JsonKeys::kKeyValidityStartTime[] = "key_validity_start_time";
const char JsonKeys::kSigHashType[] = "sig_hash_type";
const char JsonKeys::kMaskGenFunction[] = "mask_gen_function";
const char JsonKeys::kSaltLength[] = "salt_length";
const char JsonKeys::kKeySize[] = "key_size";
const char JsonKeys::kMessageMaskType[] = "message_mask_type";
const char JsonKeys::kMessageMaskSize[] = "message_mask_size";

// PublicMetadataInfo
const char JsonKeys::kPublicMetadata[] = "public_metadata";
const char JsonKeys::kValidationVersion[] = "validation_version";

// PublicMetadata
const char JsonKeys::kExitLocation[] = "exit_location";
const char JsonKeys::kServiceType[] = "service_type";
const char JsonKeys::kExpiration[] = "expiration";

// Location
const char JsonKeys::kCountry[] = "country";
const char JsonKeys::kCityGeoId[] = "city_geo_id";

// Timestamp
const char JsonKeys::kSeconds[] = "seconds";
const char JsonKeys::kNanos[] = "nanos";

}  // namespace krypton
}  // namespace privacy
