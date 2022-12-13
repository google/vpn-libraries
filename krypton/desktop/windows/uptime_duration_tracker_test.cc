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

#include "privacy/net/krypton/desktop/windows/uptime_duration_tracker.h"

#include <memory>
#include <vector>

#include "privacy/net/krypton/krypton_clock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

class UptimeDurationTrackerTest : public ::testing::Test {
  void SetUp() override {
    clock_.SetNow(absl::UniversalEpoch() + absl::Minutes(5));
    uptime_duration_tracker_ = std::make_unique<UptimeDurationTracker>(&clock_);
  }

 protected:
  FakeClock clock_ = FakeClock(absl::UniversalEpoch() + absl::Minutes(5));
  std::unique_ptr<UptimeDurationTracker> uptime_duration_tracker_;
};

TEST_F(UptimeDurationTrackerTest, DefaultsToZero) {
  ASSERT_EQ(uptime_duration_tracker_->CollectDurations().size(), 0);
}

TEST_F(UptimeDurationTrackerTest, Start_CreatesOneEntryInList) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));

  std::vector<absl::Duration> durations =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations.size(), 1);
  ASSERT_EQ(durations.front(), absl::Minutes(2));
}

TEST_F(UptimeDurationTrackerTest, StartAndStop_CreatesOneEntryInList) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));
  uptime_duration_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(2));

  std::vector<absl::Duration> durations =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations.size(), 1);
  ASSERT_EQ(durations.front(), absl::Minutes(2));
}

TEST_F(UptimeDurationTrackerTest, StartAndStop_CreatesEntriesInList) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));
  uptime_duration_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(3));
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(5));

  std::vector<absl::Duration> durations =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations.size(), 2);
  ASSERT_EQ(durations.front(), absl::Minutes(2));
  ASSERT_EQ(durations.back(), absl::Minutes(5));
}

TEST_F(UptimeDurationTrackerTest, Collect_ResetsList) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));

  std::vector<absl::Duration> durations1 =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations1.size(), 1);
  ASSERT_EQ(durations1.front(), absl::Minutes(2));

  clock_.AdvanceBy(absl::Minutes(5));

  std::vector<absl::Duration> durations2 =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations2.size(), 1);
  ASSERT_EQ(durations2.front(), absl::Minutes(5));
}

TEST_F(UptimeDurationTrackerTest, StartTwice) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(3));
  uptime_duration_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(4));

  std::vector<absl::Duration> durations =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations.size(), 1);
  ASSERT_EQ(durations.front(), absl::Minutes(5));
}

TEST_F(UptimeDurationTrackerTest, StopTwice) {
  uptime_duration_tracker_->Start();
  clock_.AdvanceBy(absl::Minutes(2));
  uptime_duration_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(3));
  uptime_duration_tracker_->Stop();
  clock_.AdvanceBy(absl::Minutes(4));

  std::vector<absl::Duration> durations =
      uptime_duration_tracker_->CollectDurations();

  ASSERT_EQ(durations.size(), 1);
  ASSERT_EQ(durations.front(), absl::Minutes(2));
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
