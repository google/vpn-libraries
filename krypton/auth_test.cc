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

#include "privacy/net/krypton/auth.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "google/protobuf/duration.proto.h"
#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/key_services.proto.h"
#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/auth_and_sign_request.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/anonymous_tokens/cpp/testing/utils.h"
#include "third_party/anonymous_tokens/proto/anonymous_tokens.proto.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {

using ::private_membership::anonymous_tokens::AnonymousTokensRsaBssaClient;
using ::private_membership::anonymous_tokens::RSABlindSignaturePublicKey;
using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::EqualsProto;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::proto::Partially;

MATCHER_P(PartiallyMatchHttpRequest, other_req,
          "Partially match JSON in an HttpRequest") {
  if (arg.url() != other_req.url()) {
    return false;
  }
  if (arg.has_json_body() || other_req.has_json_body()) {
    auto json1 = arg.json_body();
    auto json2 = other_req.json_body();

    auto json1_obj = utils::StringToJson(json1);
    auto json2_obj = utils::StringToJson(json2);

    if (!json1_obj.ok() || !json2_obj.ok()) {
      return false;
    }

    for (auto const& item : json1_obj->items()) {
      if (json2_obj->contains(item.key()) &&
          item.value() != json2_obj.value()[item.key()]) {
        return false;
      }
    }
  }
  return true;
}

class MockAuthNotification : public Auth::NotificationInterface {
 public:
  MOCK_METHOD(void, AuthSuccessful, (bool), (override));
  MOCK_METHOD(void, AuthFailure, (const absl::Status&), (override));
};

class MockAnonymousTokensRsaBssaClient : public AnonymousTokensRsaBssaClient {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<AnonymousTokensRsaBssaClient>>,
              Create, (RSABlindSignaturePublicKey&), ());
};

class AuthTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Create public key for AT library usage tests.
    // TODO This generates a standard RSA key for signatures
    // w/ no public metadata. This test should be updated when AT client
    // uses public metadata in computations during signature unblinding.
    auto keypair = private_membership::anonymous_tokens::CreateTestKey();
    keypair_ = *std::move(keypair);
    keypair_.second.set_key_version(1);
    keypair_.second.set_use_case("TEST_USE_CASE");
  }

  KryptonConfig CreateKryptonConfig(bool blind_signing,
                                    bool enable_attestation) {
    KryptonConfig config;
    config.set_zinc_url("http://www.example.com/auth");
    config.set_zinc_public_signing_key_url("http://www.example.com/publickey");
    config.set_service_type("service_type");
    config.set_enable_blind_signing(blind_signing);
    config.set_datapath_protocol(KryptonConfig::IPSEC);
    config.set_integrity_attestation_enabled(enable_attestation);
    return config;
  }
  HttpResponse fake_response_;

  void ConfigureAuth(const KryptonConfig& config) {
    auth_ = std::make_unique<Auth>(config, &http_fetcher_, &oauth_,
                                   &looper_thread_);
    auth_->RegisterNotificationHandler(&auth_notification_);

    ASSERT_OK_AND_ASSIGN(crypto_, crypto::SessionCrypto::Create(config));
  }

  void TearDown() override { auth_->Stop(); }

  HttpRequest buildAuthRequest() {
    HttpRequest request;
    request.set_url("http://www.example.com/auth");
    request.set_json_body(utils::JsonToString(buildJsonBodyForAuth()));
    return request;
  }

  // Request from Auth.
  nlohmann::json buildJsonBodyForAuth() {
    nlohmann::json json_body;
    json_body[JsonKeys::kAuthTokenKey] = "some_token";
    json_body[JsonKeys::kServiceTypeKey] = "service_type";
    return json_body;
  }

  HttpResponse buildPublicKeyResponse() {
    return buildPublicKeyResponseWithNonce(false);
  }

  HttpResponse buildPublicKeyResponseWithNonce(bool include_nonce) {
    HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");

    nlohmann::json json_body;
    // Some random public string.
    const std::string rsa_pem = absl::StrCat(
        "-----BEGIN PUBLIC KEY-----\n",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n",
        "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n",
        "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n",
        "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n",
        "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n",
        "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n",
        "wQIDAQAB\n", "-----END PUBLIC KEY-----\n");
    json_body["pem"] = rsa_pem;
    if (include_nonce) {
      json_body[JsonKeys::kAttestationNonce] = "some_nonce";
    }
    response.set_json_body(utils::JsonToString(json_body));

    return response;
  }

  // Response to Auth
  HttpResponse buildResponse() {
    HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");
    response.set_json_body(R"pb({ "jwt_token": "some_random_jwt_token" })pb");
    return response;
  }

  // Response to AT Auth Request
  HttpResponse buildATSignResponse(const HttpRequest& http_request) {
    auto initial_data_response = createGetInitialDataResponse();

    privacy::ppn::AuthAndSignRequest request;
    EXPECT_TRUE(request.ParseFromString(http_request.proto_body()));

    // Validate AuthAndSignRequest.
    EXPECT_EQ(request.oauth_token(), "some_token");
    EXPECT_EQ(request.service_type(), "service_type");
    // Phosphor does not need the public key hash if the KeyType is
    // privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE.
    EXPECT_EQ(request.key_type(), privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE);
    EXPECT_EQ(request.public_key_hash(), "");
    EXPECT_THAT(request.public_metadata_info(),
                EqualsProto(initial_data_response.public_metadata_info()));
    EXPECT_EQ(request.key_version(), keypair_.second.key_version());

    // Construct AuthAndSignResponse.
    ppn::AuthAndSignResponse auth_response;
    for (const auto& request_token : request.blinded_token()) {
      std::string decoded_blinded_token;
      EXPECT_TRUE(absl::Base64Unescape(request_token, &decoded_blinded_token));
      absl::StatusOr<std::string> serialized_token =
          // TODO As mentioned above, this is for RSA signatures
          // which don't take public metadata into account. Eventually this will
          // need to be updated.
          private_membership::anonymous_tokens::TestSign(decoded_blinded_token,
                                                         keypair_.first.get());
      EXPECT_OK(serialized_token);
      auth_response.add_blinded_token_signature(
          absl::Base64Escape(*serialized_token));
    }

    // add to http response
    privacy::krypton::HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");
    response.set_proto_body(auth_response.SerializeAsString());
    return response;
  }

  // Temporary failure
  HttpResponse buildTemporaryFailureResponse() {
    HttpResponse response;
    response.mutable_status()->set_code(500);
    response.mutable_status()->set_message("OK");
    return response;
  }

  ppn::GetInitialDataResponse createGetInitialDataResponse() {
    ppn::GetInitialDataResponse response = ParseTextProtoOrDie(R"pb(
      at_public_metadata_public_key: {},
      public_metadata_info: {
        public_metadata: {
          exit_location: { country: "US" },
          service_type: "service_type",
          expiration: { seconds: 900, nanos: 0 },
        },
        validation_version: 1
      },
      attestation: {}
    )pb");

    *response.mutable_at_public_metadata_public_key() = keypair_.second;
    return response;
  }

  HttpResponse buildInitialDataHttpResponse() {
    HttpResponse response;
    response.set_proto_body(createGetInitialDataResponse().SerializeAsString());
    response.mutable_status()->set_code(200);
    return response;
  }

  HttpResponse buildBadCityIdInitialDataHttpResponse() {
    HttpResponse response;

    auto initial_data_response = createGetInitialDataResponse();
    initial_data_response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->mutable_exit_location()
        ->set_city_geo_id("us_al_bhm");
    response.set_proto_body(initial_data_response.SerializeAsString());
    response.mutable_status()->set_code(200);
    return response;
  }

  HttpResponse buildDebugModeEnabledInitialDataHttpResponse() {
    HttpResponse response;

    auto initial_data_response = createGetInitialDataResponse();
    initial_data_response.mutable_public_metadata_info()
        ->mutable_public_metadata()
        ->set_debug_mode(ppn::PublicMetadata::DEBUG_ALL);
    response.set_proto_body(initial_data_response.SerializeAsString());
    response.mutable_status()->set_code(200);
    return response;
  }

  void inspectInitialDataResponse(
      ppn::GetInitialDataResponse initial_data_response) {
    auto expected_response = createGetInitialDataResponse();

    EXPECT_THAT(initial_data_response.public_metadata_info(),
                EqualsProto(expected_response.public_metadata_info()));
    EXPECT_EQ(initial_data_response.at_public_metadata_public_key().use_case(),
              expected_response.at_public_metadata_public_key().use_case());
    EXPECT_EQ(initial_data_response.at_public_metadata_public_key().key_size(),
              expected_response.at_public_metadata_public_key().key_size());
    EXPECT_EQ(initial_data_response.at_public_metadata_public_key().use_case(),
              expected_response.at_public_metadata_public_key().use_case());
    EXPECT_EQ(
        initial_data_response.at_public_metadata_public_key()
            .mask_gen_function(),
        expected_response.at_public_metadata_public_key().mask_gen_function());
    EXPECT_EQ(
        initial_data_response.at_public_metadata_public_key().sig_hash_type(),
        expected_response.at_public_metadata_public_key().sig_hash_type());
    EXPECT_EQ(
        initial_data_response.at_public_metadata_public_key().salt_length(),
        expected_response.at_public_metadata_public_key().salt_length());
    EXPECT_EQ(
        initial_data_response.at_public_metadata_public_key()
            .message_mask_size(),
        expected_response.at_public_metadata_public_key().message_mask_size());
  }

  HttpRequest buildInitialDataHttpRequest() {
    auto use_attestation = true;
    auto service_type = "service_type";
    auto granularity = ppn::GetInitialDataRequest::COUNTRY;
    int64_t validation_version = 1;

    InitialDataRequest request_class(use_attestation, service_type, granularity,
                                     validation_version, "some_token");

    HttpRequest request = request_class.EncodeToProto();
    request.set_url("http://www.example.com/initial_data");
    return request;
  }

  MockHttpFetcher http_fetcher_;
  MockAuthNotification auth_notification_;
  MockOAuth oauth_;
  std::unique_ptr<Auth> auth_;
  utils::LooperThread looper_thread_{"Auth test"};
  std::unique_ptr<crypto::SessionCrypto> crypto_;
  std::unique_ptr<AnonymousTokensRsaBssaClient> bssa_client_;
  std::pair<bssl::UniquePtr<RSA>,
            private_membership::anonymous_tokens::RSABlindSignaturePublicKey>
      keypair_;
};

TEST_F(AuthTest, AuthAndResponseWithAdditionalRekey) {
  ConfigureAuth(CreateKryptonConfig(/*blind_signing=*/false,
                                    /*enable_attestation=*/false));

  absl::Notification http_fetcher_done;
  const auto return_val = buildResponse();

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(http_fetcher_, PostJson(EqualsProto(buildAuthRequest())))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthSuccessful(false))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/false);

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  EXPECT_THAT(auth_->GetState(), ::testing::Eq(Auth::State::kAuthenticated));

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  // Do Authentication for rekey.
  absl::Notification http_fetcher_done_rekey;
  EXPECT_CALL(http_fetcher_, PostJson(EqualsProto(buildAuthRequest())))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthSuccessful(/*is_rekey=*/true))
      .WillOnce(InvokeWithoutArgs(&http_fetcher_done_rekey,
                                  &absl::Notification::Notify));
  auth_->Start(/*is_rekey=*/true);

  EXPECT_TRUE(
      http_fetcher_done_rekey.WaitForNotificationWithTimeout(absl::Seconds(3)));

  AuthDebugInfo debug_info;

  auth_->GetDebugInfo(&debug_info);
  ASSERT_EQ(debug_info.latency().size(), 2);
  EXPECT_GT(debug_info.latency(0).nanos(), 0);
  EXPECT_GT(debug_info.latency(1).nanos(), 0);
}

class AuthParamsTest : public AuthTest,
                       public testing::WithParamInterface<bool> {};

TEST_P(AuthParamsTest, GetOAuthTokenFailure) {
  ConfigureAuth(CreateKryptonConfig(/*blind_signing=*/false,
                                    /*enable_attestation=*/false));

  absl::Notification done;

  EXPECT_CALL(oauth_, GetOAuthToken)
      .WillOnce(Return(absl::PermissionDeniedError("Failure")));
  EXPECT_CALL(auth_notification_,
              AuthFailure(absl::InternalError("Error fetching Oauth token")))
      .WillOnce(InvokeWithoutArgs(&done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, TestFailure) {
  ConfigureAuth(CreateKryptonConfig(/*blind_signing=*/false,
                                    /*enable_attestation=*/false));

  absl::Notification http_fetcher_done;
  const auto return_val = buildTemporaryFailureResponse();

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));
  EXPECT_CALL(http_fetcher_, PostJson(EqualsProto(buildAuthRequest())))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthFailure(absl::InternalError("OK")))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  EXPECT_THAT(auth_->GetState(), ::testing::Eq(Auth::State::kUnauthenticated));
}

TEST_P(AuthParamsTest, AuthWithBlindSigning) {
  ConfigureAuth(CreateKryptonConfig(/*blind_signing=*/true,
                                    /*enable_attestation=*/false));

  absl::Notification http_fetcher_done;
  const auto return_val = buildPublicKeyResponse();
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(
                  R"pb(url: "http://www.example.com/publickey")pb"))))
      .WillOnce(::testing::Return(return_val));

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(http_fetcher_, PostJson(Partially(EqualsProto(
                                 R"pb(url: "http://www.example.com/auth")pb"))))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthSuccessful(GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, AuthWithBlindSigningFailure) {
  ConfigureAuth(CreateKryptonConfig(/*blind_signing=*/true,
                                    /*enable_attestation=*/false));

  absl::Notification http_fetcher_done;
  const auto return_val = buildTemporaryFailureResponse();
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(
                  R"pb(url: "http://www.example.com/publickey")pb"))))
      .WillOnce(::testing::Return(return_val));

  EXPECT_CALL(auth_notification_, AuthFailure(absl::InternalError("OK")))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, AuthWithAttestation) {
  ConfigureAuth(
      CreateKryptonConfig(/*blind_signing=*/true, /*enable_attestation=*/true));

  absl::Notification http_fetcher_done;

  PublicKeyRequest keyRequest(/*request_nonce=*/true, std::nullopt);

  auto httpKeyRequest = keyRequest.EncodeToProto();
  httpKeyRequest.set_url("http://www.example.com/publickey");

  // Step 0: PublicKeyRequest with nonce_request
  EXPECT_CALL(http_fetcher_, PostJson(Partially(EqualsProto(httpKeyRequest))))
      .WillOnce(::testing::Return(
          buildPublicKeyResponseWithNonce(/*include_nonce=*/true)));

  privacy::ppn::AndroidAttestationData android_attestation_data;
  android_attestation_data.set_attestation_token("some-attestation-token");
  android_attestation_data.add_hardware_backed_certs("cert1");
  android_attestation_data.add_hardware_backed_certs("cert2");

  privacy::ppn::AttestationData attestation_data;
  attestation_data.mutable_attestation_data()->set_type_url(
      "type.googleapis.com/testing.AndroidAttestationData");
  attestation_data.mutable_attestation_data()->set_value(
      android_attestation_data.SerializeAsString());

  AuthAndSignRequest auth_and_sign("some_token", "service_type", "",
                                   std::nullopt, std::nullopt, attestation_data,
                                   /*attach_oauth_as_header=*/false);

  auto request = auth_and_sign.EncodeToProto();
  request->set_url("http://www.example.com/auth");

  // Step 1: Get OAuth Token
  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(oauth_, GetAttestationData).WillOnce(Return(attestation_data));

  // Step 2: Authentication with oauth token and attestation data.
  EXPECT_CALL(http_fetcher_, PostJson(PartiallyMatchHttpRequest(*request)))
      .WillOnce(::testing::Return(buildResponse()));

  EXPECT_CALL(auth_notification_, AuthSuccessful(/*is_rekey=*/GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  // Step 3: Hit it.
  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, AuthWithApiKey) {
  auto config =
      CreateKryptonConfig(/*blind_signing=*/true, /*enable_attestation=*/true);
  config.set_api_key("testApiKey");
  ConfigureAuth(config);

  absl::Notification http_fetcher_done;

  PublicKeyRequest keyRequest(/*request_nonce=*/true,
                              std::optional("testApiKey"));

  auto httpKeyRequest = keyRequest.EncodeToProto();
  httpKeyRequest.set_url("http://www.example.com/publickey");

  // Step 0: PublicKeyRequest with nonce_request
  EXPECT_CALL(http_fetcher_, PostJson(Partially(EqualsProto(httpKeyRequest))))
      .WillOnce(::testing::Return(
          buildPublicKeyResponseWithNonce(/*include_nonce=*/true)));

  privacy::ppn::AndroidAttestationData android_attestation_data;
  android_attestation_data.set_attestation_token("some-attestation-token");
  android_attestation_data.add_hardware_backed_certs("cert1");
  android_attestation_data.add_hardware_backed_certs("cert2");

  privacy::ppn::AttestationData attestation_data;
  attestation_data.mutable_attestation_data()->set_type_url(
      "type.googleapis.com/testing.AndroidAttestationData");
  attestation_data.mutable_attestation_data()->set_value(
      android_attestation_data.SerializeAsString());

  AuthAndSignRequest auth_and_sign("some_token", "service_type", "",
                                   std::nullopt, std::nullopt, attestation_data,
                                   /*attach_oauth_as_header=*/false);

  auto request = auth_and_sign.EncodeToProto();
  request->set_url("http://www.example.com/auth");

  // Step 1: Get OAuth Token
  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(oauth_, GetAttestationData).WillOnce(Return(attestation_data));

  // Step 2: Authentication with oauth token and attestation data.
  EXPECT_CALL(http_fetcher_, PostJson(PartiallyMatchHttpRequest(*request)))
      .WillOnce(::testing::Return(buildResponse()));

  EXPECT_CALL(auth_notification_, AuthSuccessful(/*is_rekey=*/GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  // Step 3: Hit it.
  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, AuthWithOauthTokenAsHeader) {
  auto config = CreateKryptonConfig(/*blind_signing=*/true,
                                    /*enable_attestation=*/false);
  config.set_attach_oauth_token_as_header(true);

  ConfigureAuth(config);

  absl::Notification http_fetcher_done;
  const auto return_val = buildPublicKeyResponse();
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(
                  R"pb(url: "http://www.example.com/publickey")pb"))))
      .WillOnce(::testing::Return(return_val));

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));
  AuthAndSignRequest auth_and_sign("some_token", "service_type", "",
                                   std::nullopt, std::nullopt, std::nullopt,
                                   /*attach_oauth_as_header=*/true);

  auto request = auth_and_sign.EncodeToProto();
  request->set_url("http://www.example.com/auth");

  EXPECT_CALL(http_fetcher_, PostJson(PartiallyMatchHttpRequest(*request)))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthSuccessful(GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_P(AuthParamsTest, AuthWithPublicMetadataEnabled) {
  // TODO Update this test, when AT client accounts for public
  // metadata.
  auto config =
      CreateKryptonConfig(/*blind_signing=*/true, /*enable_attestation=*/true);
  config.set_api_key("testApiKey");
  config.set_public_metadata_enabled(true);
  config.set_initial_data_url("http://www.example.com/initial_data");
  ConfigureAuth(config);

  absl::Notification http_fetcher_done;
  // Step 0: RequestInitialData
  EXPECT_CALL(oauth_, GetOAuthToken).WillRepeatedly(Return("some_token"));
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(buildInitialDataHttpRequest()))))
      .WillOnce(::testing::Return(buildInitialDataHttpResponse()));

  // Step 1: AuthAndSign
  EXPECT_CALL(http_fetcher_, PostJson(Partially(EqualsProto(
                                 R"pb(url: "http://www.example.com/auth")pb"))))
      .WillOnce(Invoke([this](HttpRequest request) {
        auto response = buildATSignResponse(request);
        EXPECT_EQ(response.status().code(), 200);
        EXPECT_EQ(response.status().message(), "OK");
        EXPECT_TRUE(response.has_proto_body());
        return response;
      }));

  EXPECT_CALL(auth_notification_, AuthSuccessful(GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  // Step 2: Hit it
  auth_->Start(/*is_rekey=*/GetParam());
  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  // Step 3: Inspect values returned by auth::initial_data_response()
  auto initial_data_response = auth_->initial_data_response();
  inspectInitialDataResponse(initial_data_response);
}

TEST_P(AuthParamsTest, InitialDataRequestNonEmptyCityGeoId) {
  absl::Notification http_fetcher_done;
  auto config =
      CreateKryptonConfig(/*blind_signing=*/true, /*enable_attestation=*/true);
  config.set_api_key("testApiKey");
  config.set_public_metadata_enabled(true);
  config.set_initial_data_url("http://www.example.com/initial_data");
  config.set_ip_geo_level(ppn::COUNTRY);
  ConfigureAuth(config);

  EXPECT_CALL(oauth_, GetOAuthToken).WillRepeatedly(Return("some_token"));
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(buildInitialDataHttpRequest()))))
      .WillOnce(::testing::Return(buildBadCityIdInitialDataHttpResponse()));

  EXPECT_CALL(
      auth_notification_,
      AuthFailure(absl::InternalError(
          "Received city_geo_id when request specified other geo level.")))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());
  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  EXPECT_THAT(auth_->GetState(), ::testing::Eq(Auth::State::kUnauthenticated));
}

TEST_P(AuthParamsTest, InitialDataRequestDebugModeSpecifiedWhenNotAllowed) {
  absl::Notification http_fetcher_done;
  auto config =
      CreateKryptonConfig(/*blind_signing=*/true, /*enable_attestation=*/true);
  config.set_api_key("testApiKey");
  config.set_public_metadata_enabled(true);
  config.set_initial_data_url("http://www.example.com/initial_data");
  config.set_ip_geo_level(ppn::COUNTRY);
  config.set_debug_mode_allowed(false);
  ConfigureAuth(config);

  EXPECT_CALL(oauth_, GetOAuthToken).WillRepeatedly(Return("some_token"));
  EXPECT_CALL(http_fetcher_,
              PostJson(Partially(EqualsProto(buildInitialDataHttpRequest()))))
      .WillOnce(
          ::testing::Return(buildDebugModeEnabledInitialDataHttpResponse()));

  EXPECT_CALL(auth_notification_, AuthFailure(::testing::_))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());
  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  EXPECT_THAT(auth_->GetState(), ::testing::Eq(Auth::State::kUnauthenticated));
}

INSTANTIATE_TEST_SUITE_P(AuthWithBlindSigning, AuthParamsTest,
                         testing::Values(true, false));

}  // namespace krypton
}  // namespace privacy
