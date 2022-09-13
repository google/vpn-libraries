// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/timer_manager.h"

#include <functional>

#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace {

using ::testing::Return;
using ::testing::status::IsOkAndHolds;

class TimerManagerTest : public ::testing::Test {
 public:
  int StartATimer(int expected_timer_id, std::function<void()> callback) {
    // Expect a timer id of 0.
    EXPECT_CALL(timer_interface_,
                StartTimer(expected_timer_id, absl::Milliseconds(5)))
        .WillOnce(Return(absl::OkStatus()));
    EXPECT_THAT(timer_manager_.StartTimer(absl::Milliseconds(5), callback),
                IsOkAndHolds(expected_timer_id));
    return expected_timer_id;
  }

  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};
};

// A simple object simulating a caller for timer manager.
struct FakeTimer {
  absl::Notification notification;
  void Callback() { notification.Notify(); }
  int timer_id = -1;
};

TEST_F(TimerManagerTest, TestStartAndExpiry) {
  FakeTimer foo;

  foo.timer_id = StartATimer(0, absl::bind_front(&FakeTimer::Callback, &foo));
  EXPECT_EQ(1, timer_manager_.NumActiveTimers());

  timer_interface_.TimerExpiry(foo.timer_id);
  foo.notification.WaitForNotification();
  EXPECT_EQ(0, timer_manager_.NumActiveTimers());
}

TEST_F(TimerManagerTest, TestStartAndCancel) {
  FakeTimer foo;

  foo.timer_id = StartATimer(0, absl::bind_front(&FakeTimer::Callback, &foo));
  EXPECT_EQ(1, timer_manager_.NumActiveTimers());

  EXPECT_CALL(timer_interface_, CancelTimer(foo.timer_id));
  timer_manager_.CancelTimer(foo.timer_id);
  EXPECT_EQ(0, timer_manager_.NumActiveTimers());
}

TEST_F(TimerManagerTest, TestMultipleTimersWithExpiry) {
  FakeTimer foo;
  FakeTimer bar;
  foo.timer_id = StartATimer(0, absl::bind_front(&FakeTimer::Callback, &foo));
  bar.timer_id = StartATimer(1, absl::bind_front(&FakeTimer::Callback, &bar));
  EXPECT_EQ(2, timer_manager_.NumActiveTimers());
  // Foo timer expired.
  timer_interface_.TimerExpiry(foo.timer_id);
  foo.notification.WaitForNotification();

  // Bar timer expired.
  timer_interface_.TimerExpiry(bar.timer_id);
  bar.notification.WaitForNotification();
  EXPECT_EQ(0, timer_manager_.NumActiveTimers());
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
