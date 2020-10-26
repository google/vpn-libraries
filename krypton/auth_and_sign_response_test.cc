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

#include "privacy/net/krypton/auth_and_sign_response.h"

#include <cstddef>
#include <string>

#include "privacy/net/krypton/json_keys.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace {

using ::testing::HasSubstr;
using ::testing::status::IsOkAndHolds;
using ::testing::status::StatusIs;

constexpr char kGoldenZincResponse[] = R"string(
  {"http":{"status":{"code":200,"message":"OK"}},"json_body":{"jwt":"TODO","blinded_token_signature":["token1","token2"],"session_manager_ips":[""]}})string";

constexpr char kGoldenPublicKeyResponse[] =
    R"string({"status":{"code":200,"message":"OK"},"json_body":{"pem": "some_pem"}})string";

// TODO: Write fuzz testing of the JSON responses.
TEST(AuthAndSignResponse, TestAuthParameter) {
  AuthAndSignResponse auth_response;
  ASSERT_OK(auth_response.DecodeFromJsonObject(R"string(
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
  })string"));
  EXPECT_EQ(auth_response.jwt_token(), "some_jwt_token");
}
TEST(AuthAndSignResponse, TestAllParametersFromGolden) {
  AuthAndSignResponse auth_response;
  ASSERT_OK(auth_response.DecodeFromJsonObject(kGoldenZincResponse));
  EXPECT_EQ(auth_response.jwt_token(), "TODO");
  EXPECT_THAT(auth_response.blinded_token_signatures(),
              testing::ElementsAre("token1", "token2"));
}

TEST(PublicKeyResponse, TestSuccessful) {
  PublicKeyResponse response;
  ASSERT_OK(response.DecodeFromJsonObject(kGoldenPublicKeyResponse));
  EXPECT_EQ(response.pem(), "some_pem");
  EXPECT_OK(response.parsing_status());
}

TEST(PublicKeyResponse, TestFailure) {
  PublicKeyResponse response;
  // Test failure due to no http headers.
  EXPECT_THAT(response.DecodeFromJsonObject(R"string()string"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Error parsing HttpResponse")));
}

TEST(PublicKeyResponse, TestHttpFailure) {
  PublicKeyResponse response;
  // Test failure due to missing pem attribute.
  EXPECT_THAT(
      response.DecodeFromJsonObject(
          R"string({"status":{"code":500,"message":"Something Wrong"}})string"),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("Content obfuscated")));
}

TEST(PublicKeyResponse, TestMissingPem) {
  PublicKeyResponse response;
  // Test failure due to missing pem attribute.
  EXPECT_THAT(
      response.DecodeFromJsonObject(
          R"string({"status":{"code":200,"message":"OK"},"json_body":{}})string"),
      StatusIs(absl::StatusCode::kFailedPrecondition,
               HasSubstr("No pem field found")));
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
