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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_TRACKER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_TRACKER_H_

#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

// Utility for tracking the uptime of a particular metric over an interval.
class UptimeTracker {
 public:
  explicit UptimeTracker(KryptonClock* clock);
  ~UptimeTracker() = default;

  // Sets the uptime metric to be "started".
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  // Sets the uptime metric to be stopped, and records the current uptime into
  // the running total.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the total amount of uptime this metric had since it was last
  // collected, and resets the counters to zero.
  absl::Duration CollectDuration() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  // Clock to obtain the current time when extracting and resetting.
  KryptonClock* const clock_;

  absl::Mutex mutex_;

  // The time that this metric was last "started", or null if it is not
  // currently up.
  absl::Time start_time_ ABSL_GUARDED_BY(mutex_);

  // The total duration of how long this metric has been "up" since it was last
  // collected, not including the current run.
  absl::Duration total_time_ ABSL_GUARDED_BY(mutex_);
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_TRACKER_H_
