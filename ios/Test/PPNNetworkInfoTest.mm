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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNNetworkInfo.h"
#import "privacy/net/krypton/proto/network_info.proto.h"
#import "privacy/net/krypton/proto/network_type.proto.h"

#import <XCTest/XCTest.h>

@interface PPNNetworkInfoTest : XCTestCase
@end

@implementation PPNNetworkInfoTest

- (void)testDescriptionWithDefaultNetworkInfo {
  privacy::krypton::NetworkInfo kryptonNetworkInfo;
  PPNNetworkInfo *networkInfo = [[PPNNetworkInfo alloc] initWithNetworkInfo:kryptonNetworkInfo];
  XCTAssertNotNil(networkInfo);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNNetworkInfo: %p; networkType:0 metered:0 addressFamily:3 MTU:0 networkID:0>",
          networkInfo];
  XCTAssertEqualObjects([networkInfo description], expectedDescription);
}

- (void)testDescriptionWithNetworkInfo {
  privacy::krypton::NetworkInfo kryptonNetworkInfo;
  kryptonNetworkInfo.set_network_type(privacy::krypton::NetworkType::WIFI);
  kryptonNetworkInfo.set_is_metered(true);
  kryptonNetworkInfo.set_address_family(privacy::krypton::NetworkInfo::V6);
  kryptonNetworkInfo.set_mtu(100);
  kryptonNetworkInfo.set_network_id(10);
  PPNNetworkInfo *networkInfo = [[PPNNetworkInfo alloc] initWithNetworkInfo:kryptonNetworkInfo];
  XCTAssertNotNil(networkInfo);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNNetworkInfo: %p; networkType:1 metered:1 addressFamily:2 MTU:100 networkID:10>",
          networkInfo];
  XCTAssertEqualObjects([networkInfo description], expectedDescription);
}

@end
