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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetryManager.h"

#import <XCTest/XCTest.h>

#include "google/protobuf/duration.proto.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeDurationTracker.h"
#import "googlemac/iPhone/Shared/PPN/Test/FakePPNClock.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

@interface PPNTelemetryManagerTest : XCTestCase
@end

@implementation PPNTelemetryManagerTest {
  PPNTelemetryManager *_PPNTelemetryManager;
  FakePPNClock *_fakePPNClock;
}

- (void)setUp {
  [super setUp];
  _fakePPNClock = [[FakePPNClock alloc] init];
  _PPNTelemetryManager = [[PPNTelemetryManager alloc] initWithClock:_fakePPNClock];
}

- (void)testCollect_defaultsToZero {
  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqual(telemetry.ppnServiceUptime, 0);
  XCTAssertEqual(telemetry.ppnConnectionUptime, 0);
  XCTAssertEqual(telemetry.networkUptime, 0);
  XCTAssertEqual(telemetry.disconnectionDurations.count, (NSUInteger)0);
  XCTAssertEqual(telemetry.disconnectionCount, 0);
}

- (void)testCollect_returnsCorrectValues {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:6]];
  [_PPNTelemetryManager notifyStopped];

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
  kryptonTelemetry.set_network_switches(2);
  kryptonTelemetry.set_successful_rekeys(6);
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqual(telemetry.ppnServiceUptime, 5);
  XCTAssertEqual(telemetry.ppnConnectionUptime, 1);
  XCTAssertEqual(telemetry.networkUptime, 3);
  XCTAssertEqual(telemetry.disconnectionDurations.count, (NSUInteger)1);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
  XCTAssertEqual(telemetry.successfulRekeys, 6);
  XCTAssertEqual(telemetry.networkSwitches, 2);
  XCTAssertEqualObjects(telemetry.authLatency, @[ @(1.5) ]);
  XCTAssertEqualObjects(telemetry.oauthLatency, @[ @(2.5) ]);
  XCTAssertEqualObjects(telemetry.zincLatency, @[ @(3.5) ]);
  XCTAssertEqualObjects(telemetry.egressLatency, @[ @(4.2) ]);
}

- (void)testDisconnectionFollowedByReconnection_collectsOneDisconnection {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNTelemetryManager notifyConnected];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqualObjects(telemetry.disconnectionDurations, @[ @(1.0) ]);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
}
- (void)testDisconnectionFollowedByNetworkLossAndReconnect_collectsTwoDisconnections {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:6]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:8]];
  [_PPNTelemetryManager notifyConnected];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  NSArray<NSNumber *> *expectedDurations = @[ @(1.0), @(2.0) ];
  XCTAssertEqualObjects(telemetry.disconnectionDurations, expectedDurations);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
}

- (void)testDisconnectionFollowedbyMultipleNetworkLossesAndReconnect_collectsThreeDisconnections {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:6]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:8]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:10]];
  [_PPNTelemetryManager notifyConnected];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  NSArray<NSNumber *> *expectedDurations = @[ @(1.0), @(1.0), @(2.0) ];
  XCTAssertEqualObjects(telemetry.disconnectionDurations, expectedDurations);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
}

- (void)testDisconnectionFollowedByStop_collectsOneDisconnection {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNTelemetryManager notifyStopped];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqualObjects(telemetry.disconnectionDurations, @[ @(1.0) ]);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
}

- (void)testDisconnectionFollowedByNetworkLossAndStop_collectsOneDisconnection {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:4]];
  [_PPNTelemetryManager notifyDisconnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:6]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  [_PPNTelemetryManager notifyStopped];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqualObjects(telemetry.disconnectionDurations, @[ @(2.0) ]);
  XCTAssertEqual(telemetry.disconnectionCount, 1);
}

- (void)testNoDisconnection_shouldNotCollectDisconnectionSpan {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNTelemetryManager notifyStarted];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:2]];
  [_PPNTelemetryManager notifyNetworkAvailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  [_PPNTelemetryManager notifyConnected];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:6]];
  [_PPNTelemetryManager notifyNetworkUnavailable];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  [_PPNTelemetryManager notifyStopped];

  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  PPNTelemetry *telemetry = [_PPNTelemetryManager collect:kryptonTelemetry];

  XCTAssertEqual(telemetry.disconnectionDurations.count, (NSUInteger)0);
  XCTAssertEqual(telemetry.disconnectionCount, 0);
}

@end
