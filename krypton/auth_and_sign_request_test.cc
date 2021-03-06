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

#include "privacy/net/krypton/auth_and_sign_request.h"

#include <optional>

#include "testing/base/public/gunit.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/reader.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

// TODO: Write fuzz testing of the JSON body.
TEST(AuthAndSignRequest, TestAuthAndSignRequest) {
  AuthAndSignRequest request("abc", "123", "aaaa", absl::nullopt,
                             absl::nullopt);
  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  Json::Reader reader;

  Json::Value expected;
  reader.parse(R"string({
      "oauth_token" : "abc",
      "service_type" : "123",
   })string",
               expected);

  Json::Value actual;
  reader.parse(proto.value().json_body(), actual);

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestAuthAndSignRequestWithBlindSigning) {
  AuthAndSignRequest request("abc", "123", "aaaa", "some_blind",
                             "hash of blind");
  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  Json::Reader reader;

  Json::Value expected;
  reader.parse(R"string({
      "oauth_token" : "abc",
      "service_type" : "123",
      "blinded_token": [ "some_blind"],
      "public_key_hash" : "hash of blind"
   })string",
               expected);

  Json::Value actual;
  reader.parse(proto.value().json_body(), actual);

  EXPECT_EQ(actual, expected);
}

TEST(AuthAndSignRequest, TestPublicKeyRequest) {
  PublicKeyRequest request;
  auto proto = request.EncodeToProto();
  EXPECT_TRUE(proto);

  Json::Value expected;
  expected["get_public_key"] = true;

  Json::Reader reader;
  Json::Value actual;
  reader.parse(proto.value().json_body(), actual);

  EXPECT_EQ(actual, expected);
}

}  // namespace krypton
}  // namespace privacy
