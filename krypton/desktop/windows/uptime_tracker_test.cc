/*
 * Copyright (C) 2022 Google Inc.
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

#include "privacy/net/krypton/desktop/windows/uptime_tracker.h"

#include <memory>

#include "privacy/net/krypton/krypton_clock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

class UptimeTrackerTest : public ::testing::Test {
  void SetUp() override {
    clock_.SetNow(absl::UniversalEpoch() + absl::Minutes(5));
    uptime_tracker_ = std::make_unique<UptimeTracker>(&clock_);
  }

 protected:
  FakeClock clock_ = FakeClock(absl::UniversalEpoch() + absl::Minutes(5));
  std::unique_ptr<UptimeTracker> uptime_tracker_;
};

TEST_F(UptimeTrackerTest, Start_HasDuration) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(5));

  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(5));
}

TEST_F(UptimeTrackerTest, StartAndStop_HasDuration) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(3));

  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(2));
}

TEST_F(UptimeTrackerTest, StopWithoutStart) {
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(5));
  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::ZeroDuration());
}

TEST_F(UptimeTrackerTest, CollectDuration_ResetDuration) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(10));
  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(10));
  clock_.AdvanceBy(absl::Minutes(100));

  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(100));
}

TEST_F(UptimeTrackerTest, StartTwice) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(5));
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(10));
  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(15));
}

TEST_F(UptimeTrackerTest, StopTwice) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(5));
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(10));
  uptime_tracker_->Stop();
  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(5));
}

TEST_F(UptimeTrackerTest, CollectDurationAccumulative) {
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(5));
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(10));
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(15));
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(20));
  uptime_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(25));
  uptime_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(30));
  ASSERT_EQ(uptime_tracker_->CollectDuration(), absl::Minutes(45));
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
