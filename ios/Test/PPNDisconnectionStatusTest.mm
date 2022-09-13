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

#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNStatusDetails.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNDisconnectionStatus+Internal.h"
#import "privacy/net/krypton/proto/connection_status.proto.h"

#include "third_party/absl/status/internal/status_internal.h"
#include "third_party/absl/status/status.h"

#import <XCTest/XCTest.h>

@interface PPNDisconnectionStatusTest : XCTestCase
@end

@implementation PPNDisconnectionStatusTest

- (void)testDescriptionWithDefaultDisconnectionStatus {
  privacy::krypton::DisconnectionStatus kryptonDisconnectionStatus;
  PPNDisconnectionStatus *disconnectionStatus =
      [[PPNDisconnectionStatus alloc] initWithDisconnectionStatus:kryptonDisconnectionStatus];
  XCTAssertNotNil(disconnectionStatus);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNDisconnectionStatus: %p; disconnectionReason:(null) hasAvailableNetworks:NO>",
          disconnectionStatus];
  XCTAssertEqualObjects([disconnectionStatus description], expectedDescription);
}

- (void)testDescriptionWithDisconnectionStatus {
  privacy::krypton::DisconnectionStatus kryptonDisconnectionStatus;
  kryptonDisconnectionStatus.set_code(static_cast<int>(absl::StatusCode::kUnavailable));
  kryptonDisconnectionStatus.set_message("test_message");
  kryptonDisconnectionStatus.set_has_available_networks(YES);
  PPNDisconnectionStatus *disconnectionStatus =
      [[PPNDisconnectionStatus alloc] initWithDisconnectionStatus:kryptonDisconnectionStatus];
  XCTAssertNotNil(disconnectionStatus);
  PPNStatusDetails *testResultDetails =
      disconnectionStatus.disconnectionReason.userInfo[PPNStatusDetailsKey];
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNDisconnectionStatus: %p; disconnectionReason:Error Domain=com.google.ppn Code=14 "
          @"\"UNAVAILABLE: test_message\" UserInfo={NSLocalizedDescription=UNAVAILABLE: "
          @"test_message, PPNStatusDetails=<PPNStatusDetails: %p; "
          @"detailedErrorCode:0>} hasAvailableNetworks:YES>",
          disconnectionStatus, testResultDetails];
  XCTAssertEqualObjects([disconnectionStatus description], expectedDescription);
}

@end
