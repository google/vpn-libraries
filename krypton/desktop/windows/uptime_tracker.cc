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

#include "privacy/net/krypton/krypton_clock.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

UptimeTracker::UptimeTracker(KryptonClock* clock) : clock_(clock) {
  start_time_ = absl::UniversalEpoch();
  total_time_ = absl::ZeroDuration();
}

void UptimeTracker::Start() {
  absl::MutexLock l(&mutex_);

  // The span was started multiple times, but that's fine. For example, a
  // network may become available when there was already a network available.
  // Just consider it a no-op.
  if (start_time_ != absl::UniversalEpoch()) {
    return;
  }
  start_time_ = clock_->Now();
}

void UptimeTracker::Stop() {
  absl::MutexLock l(&mutex_);

  if (start_time_ == absl::UniversalEpoch()) {
    // The span was stopped multiple times, but that's fine. For example, we may
    // get multiple notifications that no network is available. Just consider it
    // a no-op.
    return;
  }
  // Measure the elapsed duration and add it to the running total.
  absl::Time now = clock_->Now();
  absl::Duration elapsed_time = now - start_time_;
  total_time_ = total_time_ + elapsed_time;
  // Reset the state to not be started.
  start_time_ = absl::UniversalEpoch();
}

absl::Duration UptimeTracker::CollectDuration() {
  absl::MutexLock l(&mutex_);

  // Grab the accumulated uptime and reset the counter.
  absl::Duration duration = total_time_;
  total_time_ = absl::ZeroDuration();

  // If it's still running, grab the current elapsed time and reset the start
  // time to now.
  if (start_time_ != absl::UniversalEpoch()) {
    absl::Time now = clock_->Now();
    absl::Duration elapsed_time = now - start_time_;
    duration = duration + elapsed_time;

    start_time_ = now;
  }
  return duration;
}
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
