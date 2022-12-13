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

#include <map>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "privacy/net/krypton/desktop/proto/oauth.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "privacy/net/krypton/utils/url.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace desktop {

absl::StatusOr<std::string> DesktopOAuth::GetOAuthToken() {
  absl::MutexLock l(&mutex_);
  if (IsTokenExpired()) {
    PPN_RETURN_IF_ERROR(RefreshAccessToken());
  }
  return token_response_.access_token();
}

absl::StatusOr<std::string> DesktopOAuth::GetOAuthRefreshToken() {
  absl::MutexLock l(&mutex_);
  if (token_response_.has_refresh_token()) {
    return token_response_.refresh_token();
  }

  auto refresh_token = storage_->FetchData(kPpnStorageKey);
  if (refresh_token.ok()) {
    return refresh_token.value();
  }

  if (!auth_config_.has_refresh_token()) {
    return absl::InternalError("Config does not have refresh token.");
  }
  return auth_config_.refresh_token();
}

void DesktopOAuth::UpdateRefreshToken(absl::string_view refresh_token) {
  absl::MutexLock l(&mutex_);
  auth_config_.set_refresh_token(refresh_token);
}

absl::Status DesktopOAuth::ExchangeAuthCodeForTokens(
    absl::string_view oauth_authorization_code, absl::string_view code_verifier,
    absl::string_view redirect_uri) {
  HttpRequest request;
  {
    absl::MutexLock l(&mutex_);
    std::map<std::string, std::string> url_params;
    nlohmann::json request_body;
    request_body["client_id"] = auth_config_.client_id();
    request_body["client_secret"] = auth_config_.client_secret();
    request_body["code"] = std::string(oauth_authorization_code);
    request_body["code_verifier"] = std::string(code_verifier);
    request_body["grant_type"] = "authorization_code";
    request_body["redirect_uri"] = std::string(redirect_uri);
    request = BuildHttpPostRequest(url_params, request_body);
  }

  HttpResponse response = http_fetcher_->PostJson(request);
  auto status = utils::GetStatusForHttpStatus(
      response.status().code(),
      "[InitializeOAuthTokenFlow] Authentication failed.");
  if (!status.ok()) {
    return status;
  }
  OAuthTokenResponse oauth_response;
  PPN_RETURN_IF_ERROR(
      proto2::util::JsonStringToMessage(response.json_body(), &oauth_response));
  {
    absl::MutexLock l(&mutex_);
    token_response_ = oauth_response;
    PPN_RETURN_IF_ERROR(StoreRefreshToken(token_response_.refresh_token()));
    PPN_RETURN_IF_ERROR(utils::ToProtoTime(
        clock_->Now() + absl::Seconds(token_response_.expires_in()),
        token_response_.mutable_expires_at()));
  }
  return absl::OkStatus();
}

absl::Status DesktopOAuth::InvalidateOAuthTokens() {
  absl::MutexLock l(&mutex_);
  auth_config_.clear_refresh_token();
  token_response_.Clear();
  return storage_->DeleteData(kPpnStorageKey);
}

bool DesktopOAuth::SilentlySignIn() {
  absl::MutexLock l(&mutex_);
  return RefreshAccessToken().ok();
}

absl::StatusOr<UserInfo> DesktopOAuth::GetUserInfo() {
  auto oauth_token = GetOAuthToken();
  {
    absl::MutexLock l(&mutex_);
    if (!oauth_token.ok()) {
      return absl::InternalError(
          "[GetUserInfo] Failed to retrieve OAuth Token");
    }
    if (!auth_config_.has_userinfo_endpoint()) {
      return absl::InternalError("[GetUserInfo] No UserInfo endpoint provided");
    }
    HttpRequest request;
    request.set_url(auth_config_.userinfo_endpoint());
    (*request.mutable_headers())["Authorization"] =
        absl::StrCat("Bearer ", oauth_token.value());
    HttpResponse response = http_fetcher_->PostJson(request);
    PPN_RETURN_IF_ERROR(utils::GetStatusForHttpStatus(
        response.status().code(),
        "[GetUserInfo] Failed to retrieve user info."));
    UserInfo parsed_response;
    proto2::util::JsonParseOptions options;
    options.ignore_unknown_fields = true;
    PPN_RETURN_IF_ERROR(proto2::util::JsonStringToMessage(
        response.json_body(), &parsed_response, options));
    return parsed_response;
  }
}

absl::Status DesktopOAuth::RefreshAccessToken() {
  auto refresh_token = storage_->FetchData(kPpnStorageKey);
  if (!refresh_token.ok() && !auth_config_.has_refresh_token()) {
    return absl::InternalError(
        "[RefreshAccessToken] Failed to fetch refresh_key from local storage.");
  }
  std::map<std::string, std::string> url_params;
  nlohmann::json request_body;
  request_body["client_id"] = auth_config_.client_id();
  request_body["client_secret"] = auth_config_.client_secret();
  request_body["refresh_token"] =
      refresh_token.ok() ? refresh_token.value() : auth_config_.refresh_token();
  request_body["grant_type"] = "refresh_token";
  HttpRequest request = BuildHttpPostRequest(url_params, request_body);
  HttpResponse response = http_fetcher_->PostJson(request);
  auto status = utils::GetStatusForHttpStatus(
      response.status().code(),
      "[RefreshAccessToken] "
      "Failed to retrieve credentials using stored refresh token.");
  if (!status.ok()) {
    return status;
  }
  OAuthTokenResponse parsed_response;
  auto json_status =
      proto2::util::JsonStringToMessage(response.json_body(), &parsed_response);
  if (!json_status.ok()) {
    return absl::InternalError(
        "[RefreshAccessToken] Failed to parse token response.");
  }
  token_response_ = parsed_response;
  PPN_RETURN_IF_ERROR(utils::ToProtoTime(
      absl::Now() + absl::Seconds(token_response_.expires_in()),
      token_response_.mutable_expires_at()));
  return absl::OkStatus();
}

bool DesktopOAuth::IsTokenExpired() {
  if (!token_response_.has_expires_at()) {
    return true;
  }
  absl::StatusOr<absl::Time> expires_at =
      utils::TimeFromProto(token_response_.expires_at());
  return !token_response_.has_access_token() ||
         (clock_->Now() >= expires_at.value());
}

absl::Status DesktopOAuth::StoreRefreshToken(absl::string_view refresh_token) {
  if (!storage_->StoreData(kPpnStorageKey, refresh_token).ok()) {
    return absl::InternalError(
        "[StoreRefreshToken] Failed to store refresh token.");
  }
  return absl::OkStatus();
}

HttpRequest DesktopOAuth::BuildHttpPostRequest(
    const std::map<std::string, std::string>& url_params,
    const nlohmann::json& body) {
  HttpRequest request;
  utils::URL url(auth_config_.token_endpoint());

  // marshall URL query parameters
  for (auto const& kv : url_params) {
    url.AddQueryComponent(kv.first, kv.second);
  }
  request.set_url(url.AssembleString());
  request.set_json_body(body.dump());
  return request;
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
