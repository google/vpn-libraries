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

#include "privacy/net/krypton/auth_and_sign_request.h"

#include <optional>
#include <string>

#include "google/protobuf/any.proto.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

using ::testing::EqualsProto;

// TODO: Write fuzz testing of the JSON body.
TEST(AuthAndSignRequest, TestAuthAndSignRequest) {
  AuthAndSignRequest request("abc", "123", "aaaa", std::nullopt, std::nullopt,
                             std::nullopt,
                             /*attach_oauth_as_header=*/false);

  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  ASSERT_OK_AND_ASSIGN(auto actual, utils::StringToJson(proto->json_body()));

  ASSERT_OK_AND_ASSIGN(auto expected, utils::StringToJson(R"string({
      "oauth_token" : "abc",
      "service_type" : "123"
   })string"));

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestAuthAndSignRequestWithOauthAsHeader) {
  AuthAndSignRequest request("abc", "123", "aaaa", std::nullopt, std::nullopt,
                             std::nullopt,
                             /*attach_oauth_as_header=*/true);

  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  ASSERT_OK_AND_ASSIGN(auto actual, utils::StringToJson(proto->json_body()));

  ASSERT_OK_AND_ASSIGN(auto expected, utils::StringToJson(R"string({
      "service_type" : "123"
   })string"));

  EXPECT_EQ(actual, expected);
  EXPECT_EQ(proto->headers().find("Authorization")->second, "Bearer abc");
}

TEST(AuthAndSignRequest, TestAuthAndSignRequestWithBlindSigning) {
  AuthAndSignRequest request("abc", "123", "aaaa", "some_blind",
                             "hash of blind", std::nullopt,
                             /*attach_oauth_as_header=*/false);
  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  ASSERT_OK_AND_ASSIGN(auto actual, utils::StringToJson(proto->json_body()));

  ASSERT_OK_AND_ASSIGN(auto expected, utils::StringToJson(R"string({
       "oauth_token" : "abc",
       "service_type" : "123",
       "blinded_token": ["some_blind"],
       "public_key_hash" : "hash of blind"
    })string"));

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestPublicKeyRequest) {
  PublicKeyRequest request(/*request_nonce=*/false, std::optional("apiKey"));
  auto proto = request.EncodeToProto();

  ASSERT_OK_AND_ASSIGN(auto actual, utils::StringToJson(proto.json_body()));

  nlohmann::json expected;
  expected["get_public_key"] = true;

  EXPECT_EQ(proto.headers().find("X-Goog-Api-Key")->second, "apiKey");

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestPublicKeyRequestWithNonceRequest) {
  PublicKeyRequest request(/*request_nonce=*/true, std::optional("apiKey"));
  auto proto = request.EncodeToProto();

  ASSERT_OK_AND_ASSIGN(auto actual, utils::StringToJson(proto.json_body()));

  nlohmann::json expected;
  expected["get_public_key"] = true;
  expected["request_nonce"] = true;

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestAuthAndSignRequestWithIntegrityToken) {
  privacy::ppn::AttestationData attestation_data;
  attestation_data.mutable_attestation_data()->set_type_url("foo");
  attestation_data.mutable_attestation_data()->set_value("bar");

  AuthAndSignRequest request("abc", "123", "aaaa", std::nullopt, std::nullopt,
                             attestation_data,
                             /*attach_oauth_as_header=*/false);
  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  ppn::AuthAndSignRequest actual;
  ASSERT_TRUE(actual.ParseFromString(proto->proto_body()));

  ASSERT_THAT(
      actual, EqualsProto(R"pb(
        oauth_token: "abc"
        service_type: "123"
        attestation { attestation_data { type_url: "foo" value: "bar" } }
      )pb"));
}

}  // namespace krypton
}  // namespace privacy
