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

#ifndef PRIVACY_NET_KRYPTON_JSON_KEYS_H_
#define PRIVACY_NET_KRYPTON_JSON_KEYS_H_

namespace privacy {
namespace krypton {

// Define all the JSON keys here.
class JsonKeys {
 public:
  static const char kAuthTokenKey[];
  static const char kServiceTypeKey[];
  static const char kBlindedTokensKey[];

  // AddEgressRequest
  static const char kUnblindedToken[];
  static const char kPpn[];
  static const char kUnblindedTokenSignature[];
  static const char kRegionTokenAndSignature[];
  static const char kPublicMetadata[];
  static const char kSigningKeyVersion[];
  static const char kMessageMask[];

  // AddEgressResponse
  static const char kPpnDataplane[];
  static const char kIkeDataplane[];

  // PpnDataplaneRequest
  static const char kClientPublicValue[];
  static const char kClientNonce[];
  static const char kRekeyVerificationKey[];
  static const char kSignature[];
  static const char kDownlinkSpi[];
  static const char kPreviousUplinkSpi[];
  static const char kControlPlaneSockAddr[];
  static const char kDataplaneProtocol[];
  static const char kSuite[];
  static const char kApnType[];
  static const char kDynamicMtuEnabled[];

  // PpnDataplaneResponse
  static const char kUserPrivateIp[];
  static const char kEgressPointSockAddr[];
  static const char kEgressPointPublicValue[];
  static const char kServerNonce[];
  static const char kUplinkSpi[];
  static const char kExpiry[];
  static const char kMssDetectionSockAddr[];
  static const char kTransportModeServerPort[];
  // kControlPlaneSockAddr already declared in PpnDataplaneRequest fields

  // IpRange
  static const char kIpv4[];
  static const char kIpv6[];

  // PPN
  static const char kPem[];
  static const char kBlindedTokenSignature[];
  static const char kCopperControllerHostname[];
  static const char kPublicKeyHash[];

  // IKE
  static const char kClientId[];
  static const char kSharedSecret[];
  static const char kServerAddress[];

  // Attestation
  static const char kAttestationNonce[];

  // UpdatePathInfoRequest
  static const char kSessionId[];
  static const char kUplinkMtu[];
  static const char kDownlinkMtu[];
  static const char kMtuUpdateSignature[];

  // PublicMetadata
  static const char kExitLocation[];
  static const char kServiceType[];
  static const char kExpiration[];
  static const char kDebugMode[];

  // Location
  static const char kCountry[];
  static const char kCityGeoId[];

  // Timestamp
  static const char kSeconds[];
  static const char kNanos[];

 private:
  JsonKeys() = default;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JSON_KEYS_H_
