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

#import <Foundation/Foundation.h>

/**
 * PPN error domain.
 */
FOUNDATION_EXTERN NSErrorDomain const PPNErrorDomain;

/**
 * PPN status details.
 */
FOUNDATION_EXTERN NSString *const PPNStatusDetailsKey;

/**
 * NSError codes for the PPN error domain.
 */
typedef NS_ERROR_ENUM(PPNErrorDomain, PPNErrorCode){
    PPNErrorOK = 0,
    PPNErrorCancelled = 1,
    PPNErrorUnknown = 2,
    PPNErrorInvalidArgument = 3,
    PPNErrorDeadlineExceeded = 4,
    PPNErrorNotFound = 5,
    PPNErrorAlreadyExists = 6,
    PPNErrorPermissionDenied = 7,
    PPNErrorResourceExhausted = 8,
    PPNErrorFailedPrecondition = 9,
    PPNErrorAborted = 10,
    PPNErrorOutOfRange = 11,
    PPNErrorUnimplemented = 12,
    PPNErrorInternal = 13,
    PPNErrorUnavailable = 14,
    PPNErrorDataLoss = 15,
    PPNErrorUnauthenticated = 16,
};

#ifdef __cplusplus

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {

absl::Status PPNStatusFromNSError(NSError *error);
NSError *NSErrorFromPPNStatus(absl::Status status);

}  // namespace krypton
}  // namespace privacy

#endif  // __cplusplus
