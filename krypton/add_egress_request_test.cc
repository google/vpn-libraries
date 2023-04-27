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

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/time/time.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

const char kCopperControlPlaneAddress[] = "192.168.0.10:1849";

class AddEgressRequestTest : public ::testing::Test {
 public:
  KryptonConfig config_;
};

class PpnAddEgressRequest : public AddEgressRequestTest,
                            public ::testing::WithParamInterface<bool> {};

TEST_F(PpnAddEgressRequest, TestPpnRequestBrass) {
  AddEgressRequest request(std::optional("apiKey"));

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
  params.control_plane_sockaddr = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = false;
  params.blind_message = "raw message";
  params.unblinded_token_signature = "raw message signature";
  params.region_token_and_signature = "raw region and sig";
  params.apn_type = "ppn";

  auto http_request = request.EncodeToProtoForPpn(params);

  EXPECT_EQ(http_request.headers().find("X-Goog-Api-Key")->second, "apiKey");
  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  ASSERT_OK_AND_ASSIGN(auto verification_key, crypto.GetRekeyVerificationKey());
  std::string public_value_encoded;
  std::string nonce_encoded;
  std::string verification_key_encoded;
  absl::Base64Escape(keys.public_value, &public_value_encoded);
  absl::Base64Escape(keys.nonce, &nonce_encoded);
  absl::Base64Escape(verification_key, &verification_key_encoded);

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "raw message");
  EXPECT_EQ(actual["unblinded_token_signature"], "raw message signature");
  EXPECT_EQ(actual["region_token_and_signature"], "raw region and sig");
  EXPECT_EQ(actual["ppn"]["apn_type"], "ppn");
  EXPECT_EQ(actual["ppn"]["client_public_value"], public_value_encoded);
  EXPECT_EQ(actual["ppn"]["client_nonce"], nonce_encoded);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            kCopperControlPlaneAddress);
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"], verification_key_encoded);
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"].is_null());
  EXPECT_TRUE(actual["ppn"]["public_metadata"].is_null());
  EXPECT_TRUE(actual["signing_key_version"].is_null());
}

TEST_F(PpnAddEgressRequest, TestPpnRequestBrassWithDynamicMtu) {
  AddEgressRequest request(std::optional("apiKey"));

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
  params.control_plane_sockaddr = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = false;
  params.blind_message = "raw message";
  params.unblinded_token_signature = "raw message signature";
  params.region_token_and_signature = "raw region and sig";
  params.apn_type = "ppn";
  params.dynamic_mtu_enabled = true;

  auto http_request = request.EncodeToProtoForPpn(params);

  EXPECT_EQ(http_request.headers().find("X-Goog-Api-Key")->second, "apiKey");
  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  ASSERT_OK_AND_ASSIGN(auto verification_key, crypto.GetRekeyVerificationKey());
  std::string public_value_encoded;
  std::string nonce_encoded;
  std::string verification_key_encoded;
  absl::Base64Escape(keys.public_value, &public_value_encoded);
  absl::Base64Escape(keys.nonce, &nonce_encoded);
  absl::Base64Escape(verification_key, &verification_key_encoded);

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "raw message");
  EXPECT_EQ(actual["unblinded_token_signature"], "raw message signature");
  EXPECT_EQ(actual["region_token_and_signature"], "raw region and sig");
  EXPECT_EQ(actual["ppn"]["apn_type"], "ppn");
  EXPECT_EQ(actual["ppn"]["client_public_value"], public_value_encoded);
  EXPECT_EQ(actual["ppn"]["client_nonce"], nonce_encoded);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            kCopperControlPlaneAddress);
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"], verification_key_encoded);
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"]);
  EXPECT_TRUE(actual["ppn"]["public_metadata"].is_null());
  EXPECT_TRUE(actual["signing_key_version"].is_null());
}

TEST_F(AddEgressRequestTest, TestPpnRequestBrassWithRekey) {
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  AddEgressRequest request(std::optional("apiKey"));
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.control_plane_sockaddr = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = true;
  params.signature = "some_signature";
  params.uplink_spi = 1234;
  auto http_request = request.EncodeToProtoForPpn(params);

  EXPECT_EQ(http_request.headers().find("X-Goog-Api-Key")->second, "apiKey");
  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));

  ASSERT_OK_AND_ASSIGN(auto verification_key, crypto.GetRekeyVerificationKey());
  std::string public_value_encoded;
  std::string nonce_encoded;
  std::string verification_key_encoded;
  std::string signature_encoded;
  absl::Base64Escape(keys.public_value, &public_value_encoded);
  absl::Base64Escape(keys.nonce, &nonce_encoded);
  absl::Base64Escape(verification_key, &verification_key_encoded);
  absl::Base64Escape(params.signature, &signature_encoded);

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "");
  EXPECT_EQ(actual["ppn"]["client_public_value"], public_value_encoded);
  EXPECT_EQ(actual["ppn"]["client_nonce"], nonce_encoded);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            kCopperControlPlaneAddress);
  EXPECT_EQ(actual["ppn"]["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"], verification_key_encoded);
  EXPECT_EQ(actual["ppn"]["rekey_signature"], signature_encoded);
  EXPECT_EQ(actual["ppn"]["previous_uplink_spi"], params.uplink_spi);
  EXPECT_TRUE(actual["ppn"]["dynamic_mtu_enabled"].is_null());
  EXPECT_TRUE(actual["ppn"]["public_metadata"].is_null());
  EXPECT_TRUE(actual["signing_key_version"].is_null());
}

TEST_F(AddEgressRequestTest, TestRekeyParametersWithDynamicMtu) {
  crypto::SessionCrypto crypto(config_);
  auto keys = crypto.GetMyKeyMaterial();

  AddEgressRequest request(std::optional("apiKey"),
                           AddEgressRequest::RequestDestination::kBeryllium);
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto;
  params.control_plane_sockaddr = kCopperControlPlaneAddress;
  params.dataplane_protocol = KryptonConfig::BRIDGE;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = true;
  params.signature = "some_signature";
  params.uplink_spi = 1234;
  params.country = "US";
  params.city_geo_id = "us_ca_san_diego";
  params.expiration = absl::FromUnixMillis(1002);
  params.service_type = "foo";
  params.signing_key_version = 3;
  params.debug_mode = privacy::ppn::PublicMetadata::UNSPECIFIED_DEBUG_MODE;
  auto http_request = request.EncodeToProtoForPpn(params);

  ASSERT_OK_AND_ASSIGN(auto verification_key, crypto.GetRekeyVerificationKey());
  std::string public_value_encoded;
  std::string nonce_encoded;
  std::string verification_key_encoded;
  std::string signature_encoded;
  absl::Base64Escape(keys.public_value, &public_value_encoded);
  absl::Base64Escape(keys.nonce, &nonce_encoded);
  absl::Base64Escape(verification_key, &verification_key_encoded);
  absl::Base64Escape(params.signature, &signature_encoded);

  EXPECT_EQ(http_request.headers().find("X-Goog-Api-Key")->second, "apiKey");
  ASSERT_OK_AND_ASSIGN(auto actual,
                       utils::StringToJson(http_request.json_body()));
  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "");
  EXPECT_EQ(actual["signing_key_version"], params.signing_key_version);
  EXPECT_FALSE(actual["region_token_and_signature"].is_null());
  ASSERT_TRUE(actual["ppn"].is_object());

  auto ppn = actual["ppn"];
  EXPECT_FALSE(ppn["apn_type"].is_null());
  EXPECT_EQ(ppn["client_public_value"], public_value_encoded);
  EXPECT_EQ(ppn["client_nonce"], nonce_encoded);
  EXPECT_EQ(ppn["control_plane_sock_addr"], kCopperControlPlaneAddress);
  EXPECT_EQ(ppn["downlink_spi"], crypto.downlink_spi());
  EXPECT_EQ(ppn["suite"], "AES128_GCM");
  EXPECT_EQ(ppn["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(ppn["rekey_verification_key"], verification_key_encoded);
  EXPECT_EQ(ppn["rekey_signature"], signature_encoded);
  EXPECT_EQ(ppn["previous_uplink_spi"], params.uplink_spi);
  EXPECT_TRUE(ppn["dynamic_mtu_enabled"].is_null());

  ASSERT_TRUE(actual["public_metadata"].is_object());
  auto public_metadata = actual["public_metadata"];
  EXPECT_EQ(public_metadata["exit_location"]["country"], "US");
  EXPECT_EQ(public_metadata["exit_location"]["city_geo_id"], "us_ca_san_diego");
  EXPECT_EQ(public_metadata["service_type"], "foo");
  EXPECT_EQ(public_metadata["expiration"]["seconds"], 1);
  EXPECT_EQ(public_metadata["expiration"]["nanos"], 2000000);
  EXPECT_EQ(public_metadata["debug_mode"], 0);
}

}  // namespace krypton
}  // namespace privacy
