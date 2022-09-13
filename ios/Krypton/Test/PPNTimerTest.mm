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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNTimer.h"

#import <XCTest/XCTest.h>

static NSTimeInterval const kTimerInterval = 1;

@interface PPNTimerTest : XCTestCase {
  std::unique_ptr<privacy::krypton::PPNTimer> _ppn_timer;
}
@end

@implementation PPNTimerTest

- (void)setUp {
  dispatch_queue_t callback_queue = dispatch_get_main_queue();
  _ppn_timer = std::make_unique<privacy::krypton::PPNTimer>(callback_queue);
}

- (void)testStartTimerSuccessful {
  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);
  XCTAssertTrue(_ppn_timer->IsTimerValid(1).has_value());
  XCTAssertTrue(_ppn_timer->IsTimerValid(1).value());

  // Creates another timer with a different timer id.
  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/2, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->TimerCount() == 2);
  XCTAssertTrue(_ppn_timer->IsTimerValid(2).has_value());
  XCTAssertTrue(_ppn_timer->IsTimerValid(2).value());
}

- (void)testStartTimerDuplicateTimer {
  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());

  // Create another timer with a duplicate timer_id
  auto status_start_dup = _ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval));
  XCTAssertFalse(status_start_dup.ok());
  XCTAssertEqual(status_start_dup.message(), "timer_id 1 already exists.");
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);
}

- (void)testStartTimerAndExpire {
  XCTestExpectation *expectation =
      [self expectationWithDescription:@"should call registered callback when timer expires"];

  std::function<void(int)> callBack = [self, &expectation](int) {
    XCTAssertTrue(_ppn_timer->TimerCount() == 0);
    XCTAssertFalse(_ppn_timer->IsTimerValid(1).has_value());
    [expectation fulfill];
  };
  _ppn_timer->RegisterCallback(callBack);

  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);
  XCTAssertTrue(_ppn_timer->IsTimerValid(1).has_value());
  XCTAssertTrue(_ppn_timer->IsTimerValid(1).value());

  [self waitForExpectations:@[ expectation ] timeout:kTimerInterval + 1];
}

- (void)testCancelTimer {
  XCTAssertTrue(_ppn_timer.get() != nullptr);

  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);

  _ppn_timer->CancelTimer(/*timer_id=*/2);
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);

  _ppn_timer->CancelTimer(/*timer_id=*/1);
  XCTAssertTrue(_ppn_timer->TimerCount() == 0);
}

- (void)testTimerCount {
  XCTAssertTrue(_ppn_timer->TimerCount() == 0);
  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->TimerCount() == 1);
}

- (void)testIsTimerValid {
  XCTAssertFalse(_ppn_timer->IsTimerValid(/*timer_id=*/1).has_value());
  XCTAssertTrue(_ppn_timer->StartTimer(/*timer_id=*/1, absl::Seconds(kTimerInterval)).ok());
  XCTAssertTrue(_ppn_timer->IsTimerValid(/*timer_id=*/1).has_value());
  XCTAssertTrue(_ppn_timer->IsTimerValid(/*timer_id=*/1).value());
}

@end
