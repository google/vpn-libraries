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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_DURATION_TRACKER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_DURATION_TRACKER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/uptime_tracker.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

// Utility for tracking the uptime of a particular metric over an interval.
class UptimeDurationTracker {
 public:
  explicit UptimeDurationTracker(KryptonClock* clock);
  ~UptimeDurationTracker() = default;

  // Sets the uptime metric to be "started".
  void Start();

  // Sets the uptime metric to be stopped, and records the current uptime into
  // the running total.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the List of uptimeDurations and resets list's size to zero
  std::vector<absl::Duration> CollectDurations() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  UptimeTracker uptime_tracker_;

  absl::Mutex mutex_;

  std::vector<absl::Duration> uptime_durations_ ABSL_GUARDED_BY(mutex_);

  // Adds the total uptime to the uptime durations
  void CaptureDuration() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UPTIME_DURATION_TRACKER_H_
