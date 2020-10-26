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
  AddEgressRequest request;
  // Construct an temporary auth response.
  auto auth_response = std::make_shared<AuthAndSignResponse>();

  Json::Reader reader;
  Json::Value response;
  EXPECT_TRUE(reader.parse(R"json(
  {
    "http": {
      "status":{
        "code": 200,
        "message" : "OK"
      }
    },
    "json_body": {
       "jwt": "some_jwt_token"
    }
  })json",
                           response));

  Json::FastWriter writer;
  EXPECT_OK(auth_response->DecodeFromJsonObject(writer.write(response)));
  auto json_objects = request.EncodeToJsonObjectForBridge(auth_response);
  EXPECT_TRUE(json_objects);

  Json::Value expected;
  // Order of the parameters do not matter.
  reader.parse(R"string({
      "unblinded_token" : "some_jwt_token"
   })string",
               expected);
  EXPECT_EQ(json_objects.value().json_body, expected);
}

class PpnAddEgressRequest : public AddEgressRequestTest,
                            public ::testing::WithParamInterface<bool> {};

TEST_P(PpnAddEgressRequest, TestPpnRequest) {
  AddEgressRequest request;

  // Use the actual crypto utils to ensure the base64 encoded strings are sent
  // in Json requests.
  crypto::SessionCrypto crypto;
  auto keys = crypto.GetMyKeyMaterial();

  auto auth_response = std::make_shared<AuthAndSignResponse>();
  Json::Reader reader;
  Json::Value response;
  Json::FastWriter writer;
  EXPECT_TRUE(reader.parse(R"json(
  {
    "json_body": {
      "jwt": "some_jwt_token"
    }
  })json",
                           response));
  EXPECT_OK(auth_response->DecodeFromJsonObject(writer.write(response)));
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

  auto json_objects = request.EncodeToJsonObjectForPpn(params);
  EXPECT_TRUE(json_objects);

  Json::Value expected;
  if (GetParam()) {
    expected["unblinded_token"] = "raw message";
    expected["unblinded_token_signature"] = "raw message signature";
    expected["is_unblinded_token"] = true;
  } else {
    expected["unblinded_token"] = "some_jwt_token";
  }
  expected["ppn"]["client_public_value"] = keys.public_value;
  expected["ppn"]["client_nonce"] = keys.nonce;
  expected["ppn"]["control_plane_sock_addr"] =
      absl::StrCat(kCopperControlPlaneAddress, ":1849");
  // JsonCpp expects the same type so assigning a int to uint32 will result in
  // equality mismatch.
  expected["ppn"]["downlink_spi"] = crypto.downlink_spi();
  expected["ppn"]["suite"] = "AES128_GCM";
  expected["ppn"]["dataplane_protocol"] = "BRIDGE";
  expected["ppn"]["rekey_verification_key"] =
      crypto.GetRekeyVerificationKey().ValueOrDie();
  EXPECT_EQ(json_objects.value().json_body, expected);
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
  auto json_objects = request.EncodeToJsonObjectForPpn(params);
  EXPECT_TRUE(json_objects);

  Json::Value expected;
  Json::Reader reader;
  reader.parse(R"string({
    "unblinded_token": ""
  })string",
               expected);
  expected["ppn"]["client_public_value"] = keys.public_value;
  expected["ppn"]["client_nonce"] = keys.nonce;
  expected["ppn"]["control_plane_sock_addr"] =
      absl::StrCat(kCopperControlPlaneAddress, ":1849");
  // JsonCpp expects the same type so assigning a int to uint32 will result in
  // equality mismatch.
  expected["ppn"]["downlink_spi"] = crypto.downlink_spi();
  expected["ppn"]["suite"] = "AES128_GCM";
  expected["ppn"]["dataplane_protocol"] = "BRIDGE";
  expected["ppn"]["rekey_verification_key"] =
      crypto.GetRekeyVerificationKey().ValueOrDie();
  expected["ppn"]["rekey_signature"] = params.signature;
  expected["ppn"]["previous_uplink_spi"] = params.uplink_spi;

  EXPECT_EQ(json_objects.value().json_body, expected);
}

}  // namespace krypton
}  // namespace privacy
