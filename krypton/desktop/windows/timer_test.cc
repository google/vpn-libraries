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

#include "privacy/net/krypton/desktop/windows/timer.h"

#include <windows.h>

#include <functional>

#include "privacy/net/krypton/pal/timer_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/blocking_counter.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

class TimerTest : public ::testing::Test {};

TEST_F(TimerTest, TestTimer) {
  auto result = Timer::Get()->StartTimer(1, absl::Milliseconds(60));
  EXPECT_EQ(result, absl::OkStatus());
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 1);
  Timer::Get()->CancelTimer(1);
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 0);
}

TEST_F(TimerTest, TestTimerCallbackTriggeredAutomatically) {
  absl::BlockingCounter counter{1};
  Timer::Get()->RegisterCallback([&counter](int) { counter.DecrementCount(); });
  auto result = Timer::Get()->StartTimer(1, absl::Milliseconds(60));
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 1);

  counter.Wait();

  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 0);
}

TEST_F(TimerTest, TestTimerCallbackCalledTwice) {
  Timer::Get()->RegisterCallback([](int) {});
  auto result = Timer::Get()->StartTimer(1, absl::Milliseconds(60));
  result = Timer::Get()->StartTimer(2, absl::Milliseconds(60));
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 2);

  int windowsIdTimer1 = Timer::Get()->GetWindowsTimerId(1);
  Timer::Get()->TimerCallback(windowsIdTimer1);
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 1);
  Timer::Get()->TimerCallback(windowsIdTimer1);
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 1);
  Timer::Get()->CancelTimer(2);
}

TEST_F(TimerTest, TestGetWindowsTimerId) {
  auto result = Timer::Get()->StartTimer(1, absl::Milliseconds(60));

  int windowsIdTimer = Timer::Get()->GetWindowsTimerId(1);
  EXPECT_NE(-1, windowsIdTimer);
  windowsIdTimer = Timer::Get()->GetWindowsTimerId(2);
  EXPECT_EQ(-1, windowsIdTimer);
  Timer::Get()->CancelTimer(1);
  Timer::Get()->CancelTimer(2);
  EXPECT_EQ(Timer::Get()->NumActiveTimers(), 0);
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
