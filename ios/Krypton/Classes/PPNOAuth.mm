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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNOAuth.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#import "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_format.h"

namespace privacy {
namespace krypton {

// OAuth token creation timeout in seconds.
const NSTimeInterval kDefaultOAuthTokenCreationTimeout = 30;

PPNOAuth::PPNOAuth(id<PPNOAuthManaging> oauth_manager)
    : oauth_manager_(oauth_manager), token_creation_timeout_(kDefaultOAuthTokenCreationTimeout) {}

absl::StatusOr<std::string> PPNOAuth::GetOAuthToken() {
  if (![oauth_manager_ conformsToProtocol:@protocol(PPNOAuthManaging)]) {
    return absl::FailedPreconditionError("Failed to get the OAuth token: The OAuth manager must "
                                         "conform to the PPNOAuthManaging protocol.");
  }

  dispatch_semaphore_t tokenSemaphore = dispatch_semaphore_create(0);
  NSString *__block tokenString = nil;
  NSError *__block creationError = nil;
  [oauth_manager_ oauthTokenWithCompletion:^(NSString *_Nullable token, NSError *_Nullable error) {
    tokenString = [token copy];
    creationError = error;
    dispatch_semaphore_signal(tokenSemaphore);
  }];

  BOOL semaphoreTimeout =
      dispatch_semaphore_wait(
          tokenSemaphore,
          dispatch_time(DISPATCH_TIME_NOW, (int64_t)(token_creation_timeout_ * NSEC_PER_SEC))) != 0;

  if (semaphoreTimeout) {
    return absl::InternalError("Failed to get the OAuth token: Timeout.");
  }
  if (creationError != nil) {
    std::string errorMessage = std::string(creationError.localizedDescription.UTF8String);
    return absl::InternalError(absl::StrFormat("Failed to get the OAuth token: %s", errorMessage));
  }
  if (tokenString != nil) {
    return std::string(tokenString.UTF8String);
  }
  return absl::UnknownError("Failed to get the OAuth token: Unknown error.");
}

void PPNOAuth::SetTokenCreationTimeout(NSTimeInterval token_creation_timeout) {
  token_creation_timeout_ = token_creation_timeout;
}

}  // namespace krypton
}  // namespace privacy
