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

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

const char token[] =
    "{\"type\":1,\"info\":\"INFO\",\"signature\":"
    "\"SIGNATURE\"}";
const char kCopperControlPlaneAddress[] = "192.168.0.10";
const uint32 kClientSpi = 10;

class AddEgressRequestTest : public ::testing::Test {};

TEST_F(AddEgressRequestTest, TestBridgeRequest) {
  HttpResponse http_response;
  http_response.mutable_status()->set_code(200);
  http_response.mutable_status()->set_message("OK");
  http_response.set_json_body(R"json(
  {
    "jwt": "some_jwt_token"
  }
  })json");

  // Construct an temporary auth response.
  auto auth_response = std::make_shared<AuthAndSignResponse>();
  EXPECT_OK(auth_response->DecodeFromProto(http_response));
  AddEgressRequest request;
  auto http_request = request.EncodeToProtoForBridge(auth_response);
  EXPECT_TRUE(http_request);

  Json::Value expected;
  Json::Reader reader;
  reader.parse(R"string({
      "unblinded_token" : "some_jwt_token"
   })string",
               expected);

  Json::Value actual;
  reader.parse(http_request.value().json_body(), actual);

  EXPECT_EQ(actual, expected);
}

class PpnAddEgressRequest : public AddEgressRequestTest,
                            public ::testing::WithParamInterface<bool> {};

TEST_P(PpnAddEgressRequest, TestPpnRequest) {
  AddEgressRequest request;

  // Use the actual crypto utils to ensure the base64 encoded strings are sent
  // in Json requests.
  crypto::SessionCrypto crypto;
  auto keys = crypto.GetMyKeyMaterial();

  HttpResponse response;
  response.set_json_body(R"json({"jwt": "some_jwt_token"})json");
  auto auth_response = std::make_shared<AuthAndSignResponse>();
  EXPECT_OK(auth_response->DecodeFromProto(response));

  AddEgressRequest::PpnDataplaneRequestParams params;
  params.auth_response = auth_response;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = DataplaneProtocol::BRIDGE;
  params.suite = CryptoSuite::AES128_GCM;
  params.is_rekey = false;
  if (GetParam()) {
    // Blind signing is enabled.
    params.blind_token_enabled = true;
    params.blind_message = "raw message";
    params.unblinded_token_signature = "raw message signature";
  }

  auto http_request = request.EncodeToProtoForPpn(params);
  EXPECT_TRUE(http_request);

  Json::Value actual;
  Json::Reader reader;
  reader.parse(http_request.value().json_body(), actual);

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  if (GetParam()) {
    EXPECT_EQ(actual["unblinded_token"], "raw message");
    EXPECT_EQ(actual["unblinded_token_signature"], "raw message signature");
    EXPECT_EQ(actual["is_unblinded_token"], true);
  } else {
    EXPECT_EQ(actual["unblinded_token"], "some_jwt_token");
  }
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"].asUInt(), crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
}

INSTANTIATE_TEST_SUITE_P(BlindSigning, PpnAddEgressRequest, ::testing::Bool());

TEST_F(AddEgressRequestTest, TestRekeyParameters) {
  crypto::SessionCrypto crypto;
  auto keys = crypto.GetMyKeyMaterial();

  AddEgressRequest request;
  AddEgressRequest::PpnDataplaneRequestParams params;
  auto auth_response = std::make_shared<AuthAndSignResponse>();
  params.auth_response = auth_response;
  params.crypto = &crypto;
  params.copper_control_plane_address = kCopperControlPlaneAddress;
  params.dataplane_protocol = DataplaneProtocol::BRIDGE;
  params.suite = CryptoSuite::AES128_GCM;
  params.is_rekey = true;
  params.signature = "some_signature";
  params.uplink_spi = 1234;
  auto http_request = request.EncodeToProtoForPpn(params);
  EXPECT_TRUE(http_request);

  Json::Value actual;
  Json::Reader reader;
  reader.parse(http_request.value().json_body(), actual);

  // Round-tripping through serialization causes int values to randomly be int
  // or uint, so we need to test each value separately.
  EXPECT_EQ(actual["unblinded_token"], "");
  EXPECT_EQ(actual["ppn"]["client_public_value"], keys.public_value);
  EXPECT_EQ(actual["ppn"]["client_nonce"], keys.nonce);
  EXPECT_EQ(actual["ppn"]["control_plane_sock_addr"],
            absl::StrCat(kCopperControlPlaneAddress, ":1849"));
  EXPECT_EQ(actual["ppn"]["downlink_spi"].asUInt(), crypto.downlink_spi());
  EXPECT_EQ(actual["ppn"]["suite"], "AES128_GCM");
  EXPECT_EQ(actual["ppn"]["dataplane_protocol"], "BRIDGE");
  EXPECT_EQ(actual["ppn"]["rekey_verification_key"],
            crypto.GetRekeyVerificationKey().ValueOrDie());
  EXPECT_EQ(actual["ppn"]["rekey_signature"], params.signature);
  EXPECT_EQ(actual["ppn"]["previous_uplink_spi"].asUInt(), params.uplink_spi);
}

}  // namespace krypton
}  // namespace privacy
