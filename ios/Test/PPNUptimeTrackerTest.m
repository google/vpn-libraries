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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeTracker.h"
#import "googlemac/iPhone/Shared/PPN/Test/FakePPNClock.h"

#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

#import <XCTest/XCTest.h>

@interface PPNUptimeTrackerTest : XCTestCase
@end

@implementation PPNUptimeTrackerTest {
  PPNUptimeTracker *_PPNUptimeTracker;
  FakePPNClock *_fakePPNClock;
}

- (void)setUp {
  [super setUp];
  _fakePPNClock = [[FakePPNClock alloc] init];
  _PPNUptimeTracker = [[PPNUptimeTracker alloc] initWithClock:_fakePPNClock];
}

- (void)testStart_hasDuration {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:3]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 2.0);
}

- (void)testStartAndStop_hasDuration {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 4.0);
}

- (void)testStopWithoutStart {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:11]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 0.0);
}

- (void)testCollectDuration_resetDuration {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSTimeInterval duration1 = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration1, 8.0);
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:200]];
  NSTimeInterval duration2 = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration2, 191.0);
}

- (void)testStartTwice_noOp {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:7]];
  [_PPNUptimeTracker start];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 8.0);
}

- (void)testStopTwice_noOp {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeTracker stop];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:100]];
  [_PPNUptimeTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:101]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 4.0);
}

- (void)testUptimeAccumulative {
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:1]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:5]];
  [_PPNUptimeTracker stop];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:9]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:20]];
  [_PPNUptimeTracker stop];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:31]];
  [_PPNUptimeTracker start];
  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:35]];
  [_PPNUptimeTracker stop];

  [_fakePPNClock setNow:[NSDate dateWithTimeIntervalSince1970:100]];
  NSTimeInterval duration = [_PPNUptimeTracker collectDuration];
  XCTAssertEqual(duration, 19.0);
}

@end
