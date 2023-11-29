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

#include "privacy/net/krypton/auth_and_sign_response.h"

#include <optional>
#include <string>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/anonymous_tokens/proto/anonymous_tokens.proto.h"

namespace privacy {
namespace krypton {
namespace {

using private_membership::anonymous_tokens::HashType;
using private_membership::anonymous_tokens::MaskGenFunction;
using private_membership::anonymous_tokens::MessageMaskType;
using private_membership::anonymous_tokens::RSABlindSignaturePublicKey;
using ::testing::HasSubstr;
using ::testing::status::StatusIs;

constexpr char kGoldenZincResponse[] = R"string(
  {"blinded_token_signature":["token1","token2"],"session_manager_ips":[""],"copper_controller_hostname":"test.b.g-tun.com","region_token_and_signature":"US123.sig","apn_type":"ppn"})string";

constexpr char kGoldenPublicKeyResponse[] =
    R"string({"pem": "some_pem"})string";

constexpr char kGetInitialDataResponse[] = R"string(
    {"at_public_metadata_public_key":{"use_case":"test","key_version":2,"serialized_public_key":"test","expiration_time":{"seconds":30,"nanos":0},"key_validity_start_time":{"seconds":30,"nanos":0},"sig_hash_type":"AT_HASH_TYPE_SHA256","mask_gen_function":"AT_MGF_SHA256","salt_length":2,"key_size":2,"message_mask_type":"AT_MESSAGE_MASK_CONCAT","message_mask_size":2},
    "public_metadata_info":{"public_metadata":{"exit_location":{"country":"US","city_geo_id":"us_ca_san_diego"},"service_type":"good","expiration":{"seconds":30,"nanos":0}},"validation_version":1},
    "attestation":{"attestation_nonce":"/ab"}})string";

class InitialDataResponseTest : public ::testing::Test {
 public:
  InitialDataResponseTest() = default;
  ~InitialDataResponseTest() override = default;

  ppn::GetInitialDataResponse CreateGetInitialDataResponse() {
    ppn::GetInitialDataResponse response;

    // setup at_public_metadata_public_key fields
    response.mutable_at_public_metadata_public_key()->set_use_case("test");
    response.mutable_at_public_metadata_public_key()->set_key_version(2);
    response.mutable_at_public_metadata_public_key()->set_serialized_public_key(
        "test");
    response.mutable_at_public_metadata_public_key()
        ->mutable_expiration_time()
        ->set_seconds(30);
    response.mutable_at_public_metadata_public_key()
        ->mutable_expiration_time()
        ->set_nanos(0);
    response.mutable_at_public_metadata_public_key()
        ->mutable_key_validity_start_time()
        ->set_seconds(30);
    response.mutable_at_public_metadata_public_key()
        ->mutable_key_validity_start_time()
        ->set_nanos(0);
    response.mutable_at_public_metadata_public_key()->set_sig_hash_type(
        HashType::AT_HASH_TYPE_SHA256);
    response.mutable_at_public_metadata_public_key()->set_mask_gen_function(
        MaskGenFunction::AT_MGF_SHA256);
    response.mutable_at_public_metadata_public_key()->set_salt_length(2);
    response.mutable_at_public_metadata_public_key()->set_key_size(2);
    response.mutable_at_public_metadata_public_key()->set_message_mask_type(
        MessageMaskType::AT_MESSAGE_MASK_CONCAT);
    response.mutable_at_public_metadata_public_key()->set_message_mask_size(2);

    // setup public metadata fields
    response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->mutable_exit_location()
        ->set_country("US");
    response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->mutable_exit_location()
        ->set_city_geo_id("us_ca_san_diego");
    response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->set_service_type("good");
    response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->mutable_expiration()
        ->set_seconds(30);
    response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->mutable_expiration()
        ->set_nanos(0);
    response.mutable_public_metadata_info()->set_validation_version(1);

    // setup attestation fields
    response.mutable_attestation()->set_attestation_nonce("/ab");
    return response;
  }

  void CheckDecodedGetInitialDataResponse(
      const RSABlindSignaturePublicKey& at_public_key,
      const ppn::PublicMetadataInfo& public_metadata_info,
      const ppn::PrepareAttestationData& attestation) {
    // check for set public metadata fields
    EXPECT_EQ(public_metadata_info.public_metadata().exit_location().country(),
              "US");
    EXPECT_EQ(
        public_metadata_info.public_metadata().exit_location().city_geo_id(),
        "us_ca_san_diego");
    EXPECT_EQ(public_metadata_info.public_metadata().expiration().seconds(),
              30);
    EXPECT_EQ(public_metadata_info.public_metadata().expiration().nanos(), 0);
    EXPECT_EQ(public_metadata_info.public_metadata().service_type(), "good");
    EXPECT_EQ(public_metadata_info.validation_version(), 1);

    // check for set at_public_metadata_public_key fields
    EXPECT_EQ(at_public_key.use_case(), "test");
    EXPECT_EQ(at_public_key.key_version(), 2);
    EXPECT_EQ(at_public_key.serialized_public_key(), "test");
    EXPECT_EQ(at_public_key.expiration_time().seconds(), 30);
    EXPECT_EQ(at_public_key.expiration_time().nanos(), 0);
    EXPECT_EQ(at_public_key.key_validity_start_time().seconds(), 30);
    EXPECT_EQ(at_public_key.key_validity_start_time().nanos(), 0);
    EXPECT_EQ(at_public_key.sig_hash_type(), HashType::AT_HASH_TYPE_SHA256);
    EXPECT_EQ(at_public_key.mask_gen_function(),
              MaskGenFunction::AT_MGF_SHA256);
    EXPECT_EQ(at_public_key.salt_length(), 2);
    EXPECT_EQ(at_public_key.key_size(), 2);
    EXPECT_EQ(at_public_key.message_mask_type(),
              MessageMaskType::AT_MESSAGE_MASK_CONCAT);

    // check for set attestation fields
    EXPECT_EQ(attestation.attestation_nonce(), "/ab");
  }

  HttpResponse CreateHttpResponseProtoBody(
      const ppn::GetInitialDataResponse initial_data) {
    HttpResponse response;
    response.set_proto_body(initial_data.SerializeAsString());
    return response;
  }
};

TEST(AuthAndSignResponse, TestAuthParameter) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"blinded_token_signature": ["foo"]})string");

  KryptonConfig config;
  config.add_copper_hostname_suffix("g-tun.com");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, true));
  EXPECT_THAT(auth_response.blinded_token_signatures(),
              testing::ElementsAre("foo"));
}

TEST(AuthAndSignResponse, TestAllParametersFromGolden) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(kGoldenZincResponse);

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, true));
  EXPECT_EQ(auth_response.copper_controller_hostname(), "test.b.g-tun.com");
  EXPECT_EQ(auth_response.region_token_and_signatures(), "US123.sig");
  EXPECT_EQ(auth_response.apn_type(), "ppn");
  EXPECT_THAT(auth_response.blinded_token_signatures(),
              testing::ElementsAre("token1", "token2"));
}

TEST(AuthAndSignResponse, TestEmptyHostname) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"copper_controller_hostname":""})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, true));
  EXPECT_EQ(auth_response.copper_controller_hostname(), "");
}

TEST(AuthAndSignResponse, TestWrongTypeHostname) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"copper_controller_hostname":["test.b.g-tun.com"]})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  EXPECT_THAT(AuthAndSignResponse::FromProto(proto, config, true),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "copper_controller_hostname is not a string"));
}

TEST(AuthAndSignResponse, TestWrongTypeRegionTokenAndSig) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"region_token_and_signature":["US123.sig"]})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  EXPECT_THAT(AuthAndSignResponse::FromProto(proto, config, true),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "region_token_and_signature is not a string"));
}

TEST(AuthAndSignResponse, TestWrongTypeAPNType) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"apn_type":["ppn"]})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  EXPECT_THAT(
      AuthAndSignResponse::FromProto(proto, config, true),
      StatusIs(absl::StatusCode::kInvalidArgument, "apn_type is not a string"));
}

TEST(AuthAndSignResponse, TestWrongAPNType) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"apn_type":"xxx"})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  EXPECT_THAT(
      AuthAndSignResponse::FromProto(proto, config, true),
      StatusIs(absl::StatusCode::kInvalidArgument, "unexpected apn_type"));
}

TEST(AuthAndSignResponse, TestEmptyZincResponse) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, true));
  EXPECT_EQ(auth_response.copper_controller_hostname(), "");
  EXPECT_EQ(auth_response.region_token_and_signatures(), "");
  EXPECT_EQ(auth_response.apn_type(), "");
  EXPECT_THAT(auth_response.blinded_token_signatures().size(), testing::Eq(0));
}

TEST(AuthAndSignResponse, TestEmptySuffixList) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"copper_controller_hostname":"xxx"})string");

  KryptonConfig config{};
  EXPECT_THAT(
      AuthAndSignResponse::FromProto(proto, config, true),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("suffix")));
}

TEST(AuthAndSignResponse, TestSuffixMismatch) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"copper_controller_hostname":"123.45.67.89"})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  EXPECT_THAT(
      AuthAndSignResponse::FromProto(proto, config, true),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("suffix")));
}

TEST(AuthAndSignResponse, TestSkipSuffixCheck) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"copper_controller_hostname":"123.45.67.89"})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, false));
  EXPECT_EQ(auth_response.copper_controller_hostname(), "123.45.67.89");
}

TEST(AuthAndSignResponse, TestSuffixListMultipleElements) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"copper_controller_hostname":"na.ppn-test"})string");

  KryptonConfig config{};
  config.add_copper_hostname_suffix("g-tun.com");
  config.add_copper_hostname_suffix("ppn-test");
  ASSERT_OK_AND_ASSIGN(auto auth_response,
                       AuthAndSignResponse::FromProto(proto, config, true));
  EXPECT_EQ(auth_response.copper_controller_hostname(), "na.ppn-test");
}

TEST(AuthAndSignResponse, TestMalformedJsonBody) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body("{}}");

  KryptonConfig config{};
  EXPECT_THAT(AuthAndSignResponse::FromProto(proto, config, true),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Error parsing json body")));
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

TEST(PublicKeyResponse, TestAttestationNonce) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"json({"pem": "some-pem", "attestation_nonce": "some-nonce"})json");

  PublicKeyResponse response;
  ASSERT_OK(response.DecodeFromProto(proto));
  EXPECT_EQ(response.pem(), "some-pem");
  ASSERT_TRUE(response.nonce().has_value());
  EXPECT_THAT(response.nonce(), testing::Optional(std::string("some-nonce")));
}

TEST(PublicKeyResponse, TestMalformedJsonBody) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body("{}}");

  PublicKeyResponse response;
  EXPECT_THAT(response.DecodeFromProto(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Error parsing json body")));
}

TEST_F(InitialDataResponseTest, DecodeFromProtoEmptyResponse) {
  HttpResponse http_response;
  EXPECT_THAT(http_response.proto_body(), testing::IsEmpty());
  EXPECT_THAT(http_response.json_body(), testing::IsEmpty());
  // DecodeGetInitialDataResponse
  EXPECT_EQ(DecodeGetInitialDataResponse(http_response).status(),
            absl::InvalidArgumentError("HttpResponse is missing proto_body"));
}

TEST_F(InitialDataResponseTest, HasJsonBody) {
  HttpResponse http_response;
  http_response.set_json_body(kGetInitialDataResponse);
  EXPECT_THAT(http_response.proto_body(), testing::IsEmpty());
  // DecodeGetInitialDataResponse
  EXPECT_EQ(
      DecodeGetInitialDataResponse(http_response).status(),
      absl::InvalidArgumentError("Unable to process HttpResponse.json_body()"));
}

TEST_F(InitialDataResponseTest, DecodeFromProtoProtoBodyResponse) {
  ppn::GetInitialDataResponse init_data_response_proto =
      CreateGetInitialDataResponse();
  HttpResponse http_response =
      CreateHttpResponseProtoBody(init_data_response_proto);

  EXPECT_THAT(http_response.json_body(), testing::IsEmpty());

  auto decode_status = DecodeGetInitialDataResponse(http_response);
  EXPECT_EQ(decode_status.status(), absl::OkStatus());
  RSABlindSignaturePublicKey at_public_key =
      decode_status->at_public_metadata_public_key();
  ppn::PublicMetadataInfo public_metadata_info =
      decode_status->public_metadata_info();
  ppn::PrepareAttestationData attestation = decode_status->attestation();
  CheckDecodedGetInitialDataResponse(at_public_key, public_metadata_info,
                                     attestation);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
