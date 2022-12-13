/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/desktop_oauth.h"

#include <memory>
#include <string>
#include <utility>

#include "privacy/net/krypton/desktop/fake_local_secure_storage.h"
#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "privacy/net/krypton/desktop/proto/oauth.proto.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/time/time.h"

using ::testing::_;
using ::testing::Return;

namespace privacy {
namespace krypton {
namespace desktop {

namespace {

class DesktopOAuthTest : public ::testing::Test {
  void SetUp() override {
    auth_config_ = OAuthConfig::default_instance();
    storage_ =
        std::make_unique<FakeLocalSecureStorage>(FakeLocalSecureStorage());
    auth_config_.set_client_id("client_id");
    auth_config_.set_client_secret("client_secret");
    auth_config_.set_token_endpoint("https://test.oauth.com/token");
    auth_config_.set_userinfo_endpoint("https://test.oauth.com/userinfo");
    auth_config_.add_scopes(expected_scopes_);
    http_json_response_.mutable_status()->set_code(200);
    http_json_response_.set_json_body(
        "{"
        "\"access_token\":\"" +
        expected_access_token_ +
        "\","
        "\"expires_in\":" +
        std::to_string(expected_expires_in_) +
        ","
        "\"refresh_token\":\"" +
        expected_refresh_token_ +
        "\","
        "\"token_type\":\"Bearer\","
        "\"scope\":\"" +
        expected_scopes_ +
        "\","
        "}");
    user_info_request_.set_url("https://test.oauth.com/userinfo");
    (*user_info_request_.mutable_headers())["Authorization"] =
        "Bearer " + expected_access_token_;
    user_info_response_.mutable_status()->set_code(200);
    user_info_response_.set_json_body(absl::Substitute(
        R"json({
          "email": "$0"
        })json",
        expected_userinfo_email_));
    EXPECT_CALL(http_fetcher_, PostJson(_))
        .WillRepeatedly(Return(http_json_response_));

    clock_.SetNow(absl::FromUnixSeconds(kFakeClockNowSec));
  }

 protected:
  std::string authorization_code_ = "authorization_code";
  std::string code_verifier_ = "code-verifier-123-xyz";
  std::string expected_access_token_ = "access-token-123";
  std::string expected_refresh_token_ = "refresh-token-123";
  std::string expected_scopes_ = "https://test.scope";
  std::string storage_key_ = "ppn_oauth_refresh_key";
  std::string redirect_uri_ = "https://www.redirect.uri";
  std::string expected_userinfo_email_ = "user.info.email@xxx.yyy.zzz";
  std::string expected_userinfo_display_name_ = "John Doe";
  std::string expected_userinfo_photo_url_ = "profile.image.url/user=johndoe";
  int expected_expires_in_ = 1200;
  HttpResponse http_json_response_;
  HttpResponse user_info_response_;
  HttpRequest user_info_request_;
  HttpRequest oauth_request_;
  MockHttpFetcher http_fetcher_;
  const int64_t kFakeClockNowSec = 123456789;
  FakeClock clock_ = FakeClock(absl::FromUnixSeconds(kFakeClockNowSec));
  std::unique_ptr<LocalSecureStorageInterface> storage_;
  OAuthConfig auth_config_;
};

}  // namespace

TEST_F(DesktopOAuthTest, OAuthResponseWithAuthorizationCodeSucceeds) {
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);
  ASSERT_OK(oauth_.ExchangeAuthCodeForTokens(authorization_code_,
                                             code_verifier_, redirect_uri_));
  ASSERT_OK(oauth_.GetOAuthToken());
  ASSERT_EQ(oauth_.GetOAuthToken().value(), expected_access_token_);
}

TEST_F(DesktopOAuthTest, SilentlySignInSucceeds) {
  ASSERT_OK(storage_->StoreData(storage_key_, expected_refresh_token_));
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);
  ASSERT_TRUE(oauth_.SilentlySignIn());
  ASSERT_EQ(oauth_.GetOAuthToken().value(), expected_access_token_);
}

TEST_F(DesktopOAuthTest,
       AutomaticallyTriggersRequestIfAccessTokenExpiredAndRefreshTokenExists) {
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);
  EXPECT_CALL(http_fetcher_, PostJson(_))
      .Times(2)
      .WillRepeatedly(Return(http_json_response_));
  ASSERT_OK(oauth_.ExchangeAuthCodeForTokens(authorization_code_,
                                             code_verifier_, redirect_uri_));
  ASSERT_OK(oauth_.GetOAuthToken());

  // Advancing time to when access token expires should result in
  // another call to OAuth endpoint.
  clock_.SetNow(absl::FromUnixSeconds(kFakeClockNowSec + expected_expires_in_));
  // As there is no refresh token available, we do not make a token request.
  ASSERT_OK(oauth_.GetOAuthToken());
}

TEST_F(DesktopOAuthTest, OAuthDeleteStoredDataSucceeds) {
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);
  ASSERT_OK(oauth_.ExchangeAuthCodeForTokens(authorization_code_,
                                             code_verifier_, redirect_uri_));
  ASSERT_OK(oauth_.GetOAuthToken());
  ASSERT_EQ(oauth_.GetOAuthToken().value(), expected_access_token_);
  ASSERT_OK(oauth_.InvalidateOAuthTokens());
  ASSERT_FALSE(oauth_.GetOAuthToken().ok());
}

TEST_F(DesktopOAuthTest, OAuthFetchTokenFailsIfNoOAuthFlowExecuted) {
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);
  ASSERT_FALSE(oauth_.GetOAuthToken().ok());
}

TEST_F(DesktopOAuthTest, OAuthGetUserInfo) {
  DesktopOAuth oauth_(&http_fetcher_, std::move(storage_), auth_config_,
                      &clock_);

  ASSERT_OK(oauth_.ExchangeAuthCodeForTokens(authorization_code_,
                                             code_verifier_, redirect_uri_));
  ASSERT_OK(oauth_.GetOAuthToken());
  HttpRequest userInfoRequest;
  userInfoRequest.set_url(auth_config_.userinfo_endpoint());
  (*userInfoRequest.mutable_headers())["Authorization"] =
      "Bearer " + expected_access_token_;
  EXPECT_CALL(http_fetcher_, PostJson(testing::EqualsProto(userInfoRequest)))
      .WillRepeatedly(Return(user_info_response_));
  ASSERT_OK_AND_ASSIGN(auto user_info, oauth_.GetUserInfo());
  ASSERT_EQ(user_info.email(), expected_userinfo_email_);
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
