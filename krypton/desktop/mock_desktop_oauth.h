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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_MOCK_DESKTOP_OAUTH_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_MOCK_DESKTOP_OAUTH_H_

#include <string>

#include "privacy/net/krypton/desktop/desktop_oauth.h"
#include "privacy/net/krypton/desktop/desktop_oauth_interface.h"
#include "privacy/net/krypton/desktop/proto/oauth.proto.h"
#include "testing/base/public/gmock.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace desktop {

// Mock interface for OAuth.
class MockDesktopOAuth : public DesktopOAuthInterface {
 public:
  MOCK_METHOD(absl::StatusOr<std::string>, GetOAuthToken, (), (override));
  MOCK_METHOD(absl::Status, ExchangeAuthCodeForTokens,
              (absl::string_view, absl::string_view, absl::string_view),
              (override));
  MOCK_METHOD(absl::Status, InvalidateOAuthTokens, (), (override));
  MOCK_METHOD(bool, SilentlySignIn, (), (override));
  MOCK_METHOD(absl::StatusOr<UserInfo>, GetUserInfo, ());
};

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_MOCK_DESKTOP_OAUTH_H_
