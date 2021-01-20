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

#ifndef PRIVACY_NET_KRYPTON_JSON_KEYS_H_
#define PRIVACY_NET_KRYPTON_JSON_KEYS_H_

namespace privacy {
namespace krypton {

// Define all the JSON keys here.
class JsonKeys {
 public:
  // static const char kJsonBodyKey[];
  static const char kAuthTokenKey[];
  static const char kServiceTypeKey[];
  static const char kPreviousSessionManagerIpKey[];
  static const char kSelectedSessionManagerIpKey[];
  static const char kJwtTokenKey[];
  static const char kBlindedTokensKey[];

  // Egress
  static const char kUnblindedToken[];
  static const char kBridge[];
  static const char kOperation[];
  static const char kControlPlaneSockAddr[];
  static const char kControlPlaneSockAddresses[];  // Multiple addresses
  static const char kSessionId[];
  static const char kSessionToken[];
  static const char kClientCryptoKey[];
  static const char kServerCryptoKey[];
  static const char kIpRanges[];
  static const char kDataplaneSockAddr[];
  static const char kError[];

  // Ppn
  static const char kPpn[];
  static const char kPpnDataplane[];
  static const char kClientPublicValue[];
  static const char kClientNonce[];
  static const char kUserPrivateIp[];
  static const char kEgressPointSockAddr[];
  static const char kEgressPointPublicValue[];
  static const char kServerNonce[];
  static const char kUplinkSpi[];
  static const char kDownlinkSpi[];
  static const char kExpiry[];
  static const char kIpv4[];
  static const char kIpv6[];
  static const char kDataplaneProtocol[];
  static const char kSuite[];
  static const char kSignature[];
  static const char kRekeyVerificationKey[];
  static const char kPreviousUplinkSpi[];
  static const char kPem[];
  static const char kBlindedTokenSignature[];
  static const char kIsUnblindedToken[];
  static const char kUnblindedTokenSignature[];
  static const char kPublicKeyHash[];

 private:
  JsonKeys() = default;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JSON_KEYS_H_
