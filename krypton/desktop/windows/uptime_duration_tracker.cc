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

#include "privacy/net/krypton/desktop/windows/uptime_tracker.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

UptimeDurationTracker::UptimeDurationTracker(KryptonClock* clock)
    : uptime_tracker_(clock) {}

void UptimeDurationTracker::Start() { uptime_tracker_.Start(); }

void UptimeDurationTracker::Stop() {
  absl::MutexLock l(&mutex_);
  uptime_tracker_.Stop();
  CaptureDuration();
}

std::vector<absl::Duration> UptimeDurationTracker::CollectDurations() {
  absl::MutexLock l(&mutex_);
  CaptureDuration();

  std::vector<absl::Duration> durations(uptime_durations_.begin(),
                                        uptime_durations_.end());
  uptime_durations_.clear();
  return durations;
}

void UptimeDurationTracker::CaptureDuration() {
  absl::Duration duration = uptime_tracker_.CollectDuration();
  if (duration != absl::ZeroDuration()) {
    uptime_durations_.push_back(duration);
  }
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
