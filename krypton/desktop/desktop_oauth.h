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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_DESKTOP_OAUTH_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_DESKTOP_OAUTH_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "net/proto2/util/public/json_util.h"
#include "privacy/net/krypton/desktop/desktop_oauth_interface.h"
#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "privacy/net/krypton/desktop/proto/oauth.proto.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace desktop {

class DesktopOAuth : public DesktopOAuthInterface {
 public:
  // Initializes DesktopOAuth.
  DesktopOAuth(HttpFetcherInterface* http_fetcher,
               std::unique_ptr<LocalSecureStorageInterface> storage,
               const OAuthConfig& config, KryptonClock* clock)
      : http_fetcher_(http_fetcher),
        storage_(std::move(storage)),
        auth_config_(config),
        clock_(clock) {}

  ~DesktopOAuth() override {}

  // Returns the Access Token necessary for Krypton to talk to backends.
  absl::StatusOr<std::string> GetOAuthToken() override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Updates cached refresh token.
  void UpdateRefreshToken(absl::string_view refresh_token)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the Refresh Access Token necessary for Krypton to refresh auth
  // token with OAuth.
  absl::StatusOr<std::string> GetOAuthRefreshToken()
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Called by UI to perform token flow. After the user authorizes PPN Desktop,
  // Google will return an authorization code to the app. This authorization
  // code is used to exchange for an access token and a refresh token. On flow
  // completion, an access_token and a refresh_token will be returned in the
  // response. The refresh key will be persisted to storage while the access
  // token and expiration timestamp will be kept in-memory.

  // Params:
  //  oauth_authorization_code: Code returned by Google OAuth backends after
  //                            user grants PPN Desktop authorization.
  //
  //  code_verifier: high-entropy crypto string used as part of PKCE.
  absl::Status ExchangeAuthCodeForTokens(
      absl::string_view oauth_authorization_code,
      absl::string_view code_verifier, absl::string_view redirect_uri) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Called by UI when a user logs out of PPN Desktop. This will remove the
  // stored refresh tokens currently on disk.
  absl::Status InvalidateOAuthTokens() override ABSL_LOCKS_EXCLUDED(mutex_);

  // Attempts to sign in a currently stored user. This method should be called
  // first on application start by the UI. If it successfully manages to sign
  // in the user, it will return true. False, otherwise.
  bool SilentlySignIn() override ABSL_LOCKS_EXCLUDED(mutex_);

  // Fetches user profile information using the user's oauth_token.
  absl::StatusOr<UserInfo> GetUserInfo() override ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  static constexpr char kPpnStorageKey[] = "ppn_oauth_refresh_key";
  absl::Mutex mutex_;

  HttpFetcherInterface* http_fetcher_;
  std::unique_ptr<LocalSecureStorageInterface> storage_;
  OAuthConfig auth_config_ ABSL_GUARDED_BY(mutex_);
  KryptonClock* clock_;
  OAuthTokenResponse token_response_ ABSL_GUARDED_BY(mutex_);

  // Starts OAuth Refresh flow for new access token.
  absl::Status RefreshAccessToken() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Checks to see if the access token is expired.
  bool IsTokenExpired() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Writes refresh token to storage.
  absl::Status StoreRefreshToken(absl::string_view refresh_token)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  HttpRequest BuildHttpPostRequest(
      const std::map<std::string, std::string>& url_params,
      const nlohmann::json& body) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
};

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_DESKTOP_OAUTH_H_
