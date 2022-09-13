/*
 * Copyright (C) 2021 Google Inc.
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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNOAUTH_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNOAUTH_H_

#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#include "privacy/net/krypton/pal/oauth_interface.h"

namespace privacy {
namespace krypton {

class PPNOAuth : public OAuthInterface {
 public:
  explicit PPNOAuth(id<PPNOAuthManaging> oauth_manager);

  absl::StatusOr<std::string> GetOAuthToken() override;

  absl::StatusOr<ppn::AttestationData> GetAttestationData(
      const std::string& nonce) override {
    return absl::UnimplementedError(
        "GetAttestationData() not available on iOS");
  }

  // Sets the token creation timeout. If not set, the default timeout is used.
  // This method is for test only.
  void SetTokenCreationTimeout(NSTimeInterval token_creation_timeout);

 private:
  id<PPNOAuthManaging> oauth_manager_;
  // Token creation timeout in seconds.
  NSTimeInterval token_creation_timeout_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNOAUTH_H_
