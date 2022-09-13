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

#import <XCTest/XCTest.h>
#import "privacy/net/krypton/proto/ppn_status.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"

#import <XCTest/XCTest.h>

@interface PPNErrorTest : XCTestCase
@end

@implementation PPNErrorTest

- (void)testNSErrorFromPPNStatusOk {
  absl::Status status = absl::OkStatus();
  NSError *error = privacy::krypton::NSErrorFromPPNStatus(status);
  XCTAssertNil(error);
}

- (void)testNSErrorFromPPNStatusNotOk {
  absl::Status status = absl::PermissionDeniedError("bad test");
  privacy::krypton::PpnStatusDetails input;
  input.set_detailed_error_code(privacy::krypton::PpnStatusDetails::DISALLOWED_COUNTRY);
  privacy::krypton::utils::SetPpnStatusDetails(&status, input);
  NSError *error = privacy::krypton::NSErrorFromPPNStatus(status);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, static_cast<int>(absl::StatusCode::kPermissionDenied));
  PPNStatusDetails *testResultDetails = error.userInfo[PPNStatusDetailsKey];
  XCTAssertEqual(testResultDetails.detailedErrorCode, PPNDetailedErrorCodeDisallowedCountry);
}

@end
