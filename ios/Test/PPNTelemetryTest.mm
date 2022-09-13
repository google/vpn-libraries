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

#include "google/protobuf/duration.proto.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNTelemetry.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetry+Internal.h"

#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"

#import <XCTest/XCTest.h>

@interface PPNTelemetryTest : XCTestCase
@end

@implementation PPNTelemetryTest

- (void)testDescriptionWithDefaultKryptonTelemetry {
  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  PPNTelemetry *ppnTelemetry =
      [[PPNTelemetry alloc] initWithKryptonTelemetry:kryptonTelemetry
                                       serviceUptime:0.0
                                    connectionUptime:(NSTimeInterval)0.0
                                       networkUptime:(NSTimeInterval)0.0
                              disconnectionDurations:(NSArray<NSNumber *> *)@[]
                                  disconnectionCount:(NSInteger)0.0];
  XCTAssertNotNil(ppnTelemetry);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNTelemetry: %p; authLatency: oauthLatency: zincLatency: egressLatency: "
          @"networkSwitches:0 successfulRekeys:0 serviceUptime:0.000000 connectionUptime:0.000000 "
          @"networkUptime:0.000000 disconnectionDurations: disconnectionCount:0>",
          ppnTelemetry];
  XCTAssertEqualObjects([ppnTelemetry description], expectedDescription);
}

- (void)testDescriptionWithKryptonTelemetry {
  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  google::protobuf::Duration duration;
  duration.set_seconds(1);
  duration.set_nanos(500000000);
  *kryptonTelemetry.add_auth_latency() = duration;
  duration.set_seconds(2);
  *kryptonTelemetry.add_oauth_latency() = duration;
  duration.set_seconds(3);
  *kryptonTelemetry.add_zinc_latency() = duration;
  duration.set_seconds(4);
  duration.set_nanos(200000000);
  *kryptonTelemetry.add_egress_latency() = duration;
  kryptonTelemetry.set_network_switches(5);
  kryptonTelemetry.set_successful_rekeys(6);
  PPNTelemetry *ppnTelemetry = [[PPNTelemetry alloc] initWithKryptonTelemetry:kryptonTelemetry
                                                                serviceUptime:1.0
                                                             connectionUptime:2.0
                                                                networkUptime:4.5
                                                       disconnectionDurations:@[ @(3.2) ]
                                                           disconnectionCount:2];
  XCTAssertNotNil(ppnTelemetry);
  NSString *expectedDescription = [[NSString alloc]
      initWithFormat:
          @"<PPNTelemetry: %p; authLatency:1.5 oauthLatency:2.5 zincLatency:3.5 egressLatency:4.2 "
          @"networkSwitches:5 successfulRekeys:6 serviceUptime:1.000000 connectionUptime:2.000000 "
          @"networkUptime:4.500000 disconnectionDurations:3.2 disconnectionCount:2>",
          ppnTelemetry];
  XCTAssertEqualObjects(
      [[ppnTelemetry description]
          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]],
      expectedDescription);
}

@end
