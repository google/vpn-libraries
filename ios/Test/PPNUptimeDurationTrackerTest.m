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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeDurationTracker.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeTracker.h"
#import "googlemac/iPhone/Shared/PPN/Test/FakePPNClock.h"

#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

#import <XCTest/XCTest.h>

@interface PPNUptimeDurationTrackerTest : XCTestCase
@end

@implementation PPNUptimeDurationTrackerTest {
  PPNUptimeDurationTracker *_PPNUptimeDurationTracker;
  FakePPNClock *_fakePPNClock;
}

- (void)setUp {
  [super setUp];
  _fakePPNClock = [[FakePPNClock alloc] init];
  _PPNUptimeDurationTracker = [[PPNUptimeDurationTracker alloc] initWithClock:_fakePPNClock];
}

- (void)testDefaultsToZero {
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 0);
}

- (void)testStart_createsOneEntryInList {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 1);
  XCTAssertEqualObjects(durations, @[ [NSNumber numberWithDouble:8.0] ]);
}

- (void)testStartAndStop_createsOneEntryInList {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeDurationTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 1);
  NSArray<NSNumber *> *expectedDurations = @[ @(4.0) ];
  XCTAssertEqualObjects(durations, expectedDurations);
}

- (void)testMultipleStartAndStop_createsEntriesInList {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeDurationTracker stop];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  [_PPNUptimeDurationTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:20]];
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 2);
  NSArray<NSNumber *> *expectedDurations = @[ @(4.0), @(9.0) ];
  XCTAssertEqualObjects(durations, expectedDurations);
}

- (void)testCollect_resetsList {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSArray<NSNumber *> *durations1 = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations1.count, 1);
  XCTAssertEqualObjects(durations1, @[ @(8.0) ]);

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:20]];
  NSArray<NSNumber *> *durations2 = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations2.count, 1);
  XCTAssertEqualObjects(durations2, @[ @(11.0) ]);
}

- (void)testStartTwice_noOp {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  [_PPNUptimeDurationTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:20]];
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 1);
  XCTAssertEqualObjects(durations, @[ @(19.0) ]);
}

- (void)testStopTwice_noOp {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeDurationTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  [_PPNUptimeDurationTracker stop];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:15]];
  [_PPNUptimeDurationTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:20]];
  NSArray<NSNumber *> *durations = [_PPNUptimeDurationTracker collectDurations];
  XCTAssertEqual(durations.count, 1);
  XCTAssertEqualObjects(durations, @[ @(8.0) ]);
}

@end
