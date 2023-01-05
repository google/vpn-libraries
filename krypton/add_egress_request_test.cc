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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

const char kCopperControlPlaneAddress[] = "192.168.0.10";

class AddEgressRequestTest : public ::testing::Test {
 public:
  KryptonConfig config_;
};

class PpnAddEgressRequest : public AddEgressRequestTest,
                            public ::testing::WithParamInterface<bool> {};

TEST_F(PpnAddEgressRequest, TestPpnRequest) {
  AddEgressRequest request;

  // Use the actual crypto utils to ensure the base64 encoded strings are sent
  // in Json requests.
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  HttpResponse response;
  response.set_json_body(R"json({})json");
  KryptonConfig config;
  config.add_copper_hostname_suffix("g-tun.com");

  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = false;
  params.blind_message = "raw message";
  params.unblinded_token_signature = "raw message signature";
  params.region_token_and_signature = "raw region and sig";
  params.apn_type = "ppn";

  auto http_request = request.EncodeToProtoForPpn(params);

  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "raw message");
  EXPECT_EQ(actual["unblinded_token_signature"], "raw message signature");
  EXPECT_EQ(actual["region_token_and_signature"], "raw region and sig");
  EXPECT_EQ(actual["ppn"]["apn_type"], "ppn");
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"].is_null());
}

TEST_F(PpnAddEgressRequest, TestPpnRequestWithDynamicMtu) {
  AddEgressRequest request;

  // Use the actual crypto utils to ensure the base64 encoded strings are sent
  // in Json requests.
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  HttpResponse response;
  response.set_json_body(R"json({})json");
  KryptonConfig config;
  config.add_copper_hostname_suffix("g-tun.com");

  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = false;
  params.blind_message = "raw message";
  params.unblinded_token_signature = "raw message signature";
  params.region_token_and_signature = "raw region and sig";
  params.apn_type = "ppn";
  params.dynamic_mtu_enabled = true;

  auto http_request = request.EncodeToProtoForPpn(params);

  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "raw message");
  EXPECT_EQ(actual["unblinded_token_signature"], "raw message signature");
  EXPECT_EQ(actual["region_token_and_signature"], "raw region and sig");
  EXPECT_EQ(actual["ppn"]["apn_type"], "ppn");
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"]);
}

TEST_F(AddEgressRequestTest, TestRekeyParameters) {
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  AddEgressRequest request;
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = true;
  params.signature = "some_signature";
  params.uplink_spi = 1234;
  auto http_request = request.EncodeToProtoForPpn(params);

  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "");
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
  EXPECT_EQ(actual["ppn"]["rekey_signature"], params.signature);
  EXPECT_EQ(actual["ppn"]["previous_uplink_spi"], params.uplink_spi);
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"].is_null());
}

TEST_F(AddEgressRequestTest, TestRekeyParametersWithDynamicMtu) {
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  AddEgressRequest request;
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = true;
  params.signature = "some_signature";
  params.uplink_spi = 1234;
  params.dynamic_mtu_enabled = true;
  auto http_request = request.EncodeToProtoForPpn(params);

  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));
  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "");
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
  EXPECT_EQ(actual["ppn"]["rekey_signature"], params.signature);
  EXPECT_EQ(actual["ppn"]["previous_uplink_spi"], params.uplink_spi);
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"]);
}

}  // namespace krypton
}  // namespace privacy
