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

#include "privacy/net/krypton/auth.h"

#include <memory>
#include <string>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
using ::testing::_;
using ::testing::Eq;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

class HttpFetcherImplForTest : public HttpFetcherInterface {
 public:
  MOCK_METHOD(std::string, PostJson,
              (absl::string_view, const Json::Value&, const Json::Value&),
              (override));
};

class MockAuthNotification : public Auth::NotificationInterface {
 public:
  MOCK_METHOD(void, AuthSuccessful, (bool), (override));
  MOCK_METHOD(void, AuthFailure, (const absl::Status&), (override));
};

class AuthTest : public ::testing::Test {
 public:
  void SetUp() override {
    config_.set_zinc_url("http://www.example.com/auth");
    config_.set_zinc_public_signing_key_url("http://www.example.com/publickey");
    config_.set_service_type("service_type");
    auth_ = absl::make_unique<Auth>(&config_, &http_fetcher_, &oauth_,
                                    &looper_thread_);
    auth_->RegisterNotificationHandler(&auth_notification_);
    auth_->SetCrypto(&crypto_);
  }

  void TearDown() override { auth_->Stop(); }

  Json::Value buildHttpHeaders() {
    Json::Value headers;
    // Empty headers.
    return headers;
  }
  // Request from Auth.
  Json::Value buildJsonBodyForAuth() {
    Json::Value json_body;
    json_body[JsonKeys::kAuthTokenKey] = "some_token";
    json_body[JsonKeys::kServiceTypeKey] = "service_type";

    return json_body;
  }

  Json::Value buildPublicKeyResponse() {
    Json::Value response;
    Json::Value status;
    status["code"] = 200;
    status["message"] = "OK";
    response["status"] = status;
    Json::Value json_body;
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
    response["json_body"] = json_body;
    return response;
  }
  // Response to Auth
  Json::Value buildResponse() {
    Json::Value response;
    Json::Value status;
    status["code"] = 200;
    status["message"] = "OK";
    response["status"] = status;
    Json::Value json_body;
    json_body["jwt_token"] = "some_random_jwt_token";
    response["json_body"] = json_body;
    return response;
  }

  // Permanent failure
  Json::Value buildPermanentFailureResponse() {
    Json::Value response;
    Json::Value status;
    status["code"] = 403;
    status["message"] = "OK";
    response["status"] = status;
    return response;
  }

  // Permanent failure
  Json::Value buildTemporarytFailureResponse() {
    Json::Value response;
    Json::Value status;
    status["code"] = 500;
    status["message"] = "OK";
    response["status"] = status;
    return response;
  }

  HttpFetcherImplForTest http_fetcher_;
  MockAuthNotification auth_notification_;
  MockOAuth oauth_;
  std::unique_ptr<Auth> auth_;
  KryptonConfig config_;
  utils::LooperThread looper_thread_{"Auth test"};
  crypto::SessionCrypto crypto_;
};

TEST_F(AuthTest, AuthAndResponseWithAdditionalRekey) {
  absl::Notification init_done;
  absl::Notification http_fetcher_done;
  Json::FastWriter writer;
  const std::string& return_val = writer.write(buildResponse());

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(http_fetcher_,
              PostJson(Eq("http://www.example.com/auth"),
                       Eq(buildHttpHeaders()), Eq(buildJsonBodyForAuth())))
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
  EXPECT_CALL(http_fetcher_,
              PostJson(Eq("http://www.example.com/auth"),
                       Eq(buildHttpHeaders()), Eq(buildJsonBodyForAuth())))
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
  absl::Notification init_done;
  absl::Notification http_fetcher_done;
  Json::FastWriter writer;
  const std::string& return_val =
      writer.write(buildTemporarytFailureResponse());

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));
  EXPECT_CALL(http_fetcher_,
              PostJson(Eq("http://www.example.com/auth"),
                       Eq(buildHttpHeaders()), Eq(buildJsonBodyForAuth())))
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
  config_.set_enable_blind_signing(true);

  Json::FastWriter writer;
  absl::Notification http_fetcher_done;
  const std::string& return_val = writer.write(buildPublicKeyResponse());
  EXPECT_CALL(http_fetcher_, PostJson(Eq("http://www.example.com/publickey"),
                                      Eq(buildHttpHeaders()), _))
      .WillOnce(::testing::Return(return_val));

  EXPECT_CALL(oauth_, GetOAuthToken).WillOnce(Return("some_token"));

  EXPECT_CALL(http_fetcher_, PostJson(Eq("http://www.example.com/auth"),
                                      Eq(buildHttpHeaders()), _))
      .WillOnce(::testing::Return(return_val));
  EXPECT_CALL(auth_notification_, AuthSuccessful(GetParam()))
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  auth_->Start(/*is_rekey=*/GetParam());

  EXPECT_TRUE(
      http_fetcher_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

INSTANTIATE_TEST_SUITE_P(AuthWithBlindSigning, AuthParamsTest,
                         testing::Values(true, false));
}  // namespace krypton
}  // namespace privacy
