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

#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNStatusDetails.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNStatusDetails+Internal.h"

#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"

NSErrorDomain const PPNErrorDomain = @"com.google.ppn";
NSString *const PPNStatusDetailsKey = @"PPNStatusDetails";

namespace privacy {
namespace krypton {

absl::Status PPNStatusFromNSError(NSError *error) {
  if (![PPNErrorDomain isEqualToString:error.domain]) {
    return absl::InternalError(error.localizedDescription.UTF8String);
  }
  absl::StatusCode code = static_cast<absl::StatusCode>(error.code);
  return absl::Status(code, error.localizedDescription.UTF8String);
}

NSError *NSErrorFromPPNStatus(absl::Status status) {
  if (status.ok()) {
    return nil;
  }

  std::string description = status.ToString();
  NSDictionary<NSString *, id> *userInfo = @{
    NSLocalizedDescriptionKey : @(description.c_str()),
    PPNStatusDetailsKey :
        [[PPNStatusDetails alloc] initWithPpnStatusDetails:utils::GetPpnStatusDetails(status)],
  };

  NSError *error = [[NSError alloc] initWithDomain:PPNErrorDomain
                                              code:status.raw_code()
                                          userInfo:userInfo];
  return error;
}

}  // namespace krypton
}  // namespace privacy
