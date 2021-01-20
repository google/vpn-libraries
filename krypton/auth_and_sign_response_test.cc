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
using ::testing::status::StatusIs;

constexpr char kGoldenZincResponse[] = R"string(
  {"jwt":"TODO","blinded_token_signature":["token1","token2"],"session_manager_ips":[""]})string";

constexpr char kGoldenPublicKeyResponse[] =
    R"string({"pem": "some_pem"}})string";

// TODO: Write fuzz testing of the JSON body.
TEST(AuthAndSignResponse, TestAuthParameter) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"jwt": "some_jwt_token"})string");

  AuthAndSignResponse auth_response;
  ASSERT_OK(auth_response.DecodeFromProto(proto));
  EXPECT_EQ(auth_response.jwt_token(), "some_jwt_token");
}

TEST(AuthAndSignResponse, TestAllParametersFromGolden) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(kGoldenZincResponse);

  AuthAndSignResponse auth_response;
  ASSERT_OK(auth_response.DecodeFromProto(proto));
  EXPECT_EQ(auth_response.jwt_token(), "TODO");
  EXPECT_THAT(auth_response.blinded_token_signatures(),
              testing::ElementsAre("token1", "token2"));
}

TEST(PublicKeyResponse, TestSuccessful) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(kGoldenPublicKeyResponse);

  PublicKeyResponse response;
  ASSERT_OK(response.DecodeFromProto(proto));
  EXPECT_EQ(response.pem(), "some_pem");
  EXPECT_OK(response.parsing_status());
}

TEST(PublicKeyResponse, TestMissingBody) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");

  PublicKeyResponse response;
  EXPECT_THAT(response.DecodeFromProto(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("response missing json body")));
}

TEST(PublicKeyResponse, TestEmptyBody) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body("");

  PublicKeyResponse response;
  EXPECT_THAT(response.DecodeFromProto(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("response missing json body")));
}

TEST(PublicKeyResponse, TestMissingPem) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body("{}");

  PublicKeyResponse response;
  // Test failure due to missing pem attribute.
  EXPECT_THAT(
      response.DecodeFromProto(proto),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("missing pem")));
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
