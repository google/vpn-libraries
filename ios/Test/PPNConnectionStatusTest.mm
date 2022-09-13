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

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNConnectionStatus+Internal.h"
#import "privacy/net/krypton/proto/connection_status.proto.h"
#import "privacy/net/krypton/proto/network_type.proto.h"

#import <XCTest/XCTest.h>

@interface PPNConnectionStatusTest : XCTestCase
@end

@implementation PPNConnectionStatusTest

- (void)testDescriptionWithDefaultConnectionStatus {
  privacy::krypton::ConnectionStatus kryptonConnectionStatus;
  PPNConnectionStatus *connectionStatus =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:kryptonConnectionStatus];
  XCTAssertNotNil(connectionStatus);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:@"<PPNConnectionStatus: %p; networkType:0 security:0 quality:0>",
                     connectionStatus];
  XCTAssertEqualObjects([connectionStatus description], expectedDescription);
}

- (void)testDescriptionWithConnectionStatus {
  privacy::krypton::ConnectionStatus kryptonConnectionStatus;
  kryptonConnectionStatus.set_network_type(privacy::krypton::NetworkType::CELLULAR);
  kryptonConnectionStatus.set_security(privacy::krypton::ConnectionStatus::SECURE);
  kryptonConnectionStatus.set_quality(privacy::krypton::ConnectionStatus::GOOD);
  PPNConnectionStatus *connectionStatus =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:kryptonConnectionStatus];
  XCTAssertNotNil(connectionStatus);
  NSString *expectedDescription =
      [[NSString alloc] initWithFormat:@"<PPNConnectionStatus: %p; "
                                       @"networkType:2 security:1 quality:2>",
                                       connectionStatus];
  XCTAssertEqualObjects([connectionStatus description], expectedDescription);
}

@end
