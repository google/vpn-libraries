// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.internal;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Utility for tracking the uptime of a particular metric over an interval. */
class UptimeDurationTracker {
  private static final String TAG = "UptimeDurationTracker";
  private List<Duration> uptimeDurations = new ArrayList<>();
  private final UptimeTracker uptimeTracker = new UptimeTracker();
  private final Object lock = new Object();

  /** Sets the uptime metric to be "started". */
  public void start(Clock clock) {
    synchronized (lock) {
      uptimeTracker.start(clock);
    }
  }

  /** Sets the uptime metric to be stopped. */
  public void stop(Clock clock) {
    synchronized (lock) {
      uptimeTracker.stop(clock);
      captureDuration(clock);
    }
  }

  /** Adds the total uptime to the uptime durations */
  private void captureDuration(Clock clock) {
    Duration duration = uptimeTracker.collectDuration(clock);
    if (!duration.isZero()) {
      uptimeDurations.add(duration);
    }
  }

  /** Returns the List of uptimeDurations and resets list's size to zero. */
  public List<Duration> collectDurations(Clock clock) {
    synchronized (lock) {
      captureDuration(clock);
      List<Duration> durations = uptimeDurations;
      uptimeDurations = new ArrayList<>();
      return durations;
    }
  }
}
