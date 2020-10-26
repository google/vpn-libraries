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

import androidx.annotation.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** Utility for tracking the uptime of a particular metric over an interval. */
class UptimeTracker {
  private static final String TAG = "UptimeTracker";

  // The time that this metric was last "started", or null if it is not currently up.
  @Nullable private Instant startTime;

  // The total duration of how long this metric has been "up" since it was last collected, not
  // including the current run.
  private Duration totalTime = Duration.ZERO;

  private static final Object lock = new Object();

  /** Sets the uptime metric to be "started". */
  public void start(Clock clock) {
    synchronized (lock) {
      if (startTime != null) {
        // The span was started multiple times, but that's fine. For example, a network may become
        // available when there was already a network available. Just consider it a no-op.
        return;
      }

      startTime = Instant.now(clock);
    }
  }

  /**
   * Sets the uptime metric to be stopped, and records the current uptime into the running total.
   */
  public void stop(Clock clock) {
    synchronized (lock) {
      if (startTime == null) {
        // The span was stopped multiple times, but that's fine. For example, we may get multiple
        // notifications that no network is available. Just consider it a no-op.
        return;
      }

      // Measure the elapsed duration and add it to the running total.
      Instant now = Instant.now(clock);
      Duration elapsedTime = Duration.between(startTime, now);
      totalTime = totalTime.plus(elapsedTime);

      // Reset the state to not be started.
      startTime = null;
    }
  }

  /**
   * Returns the total amount of uptime this metric had since it was last collected, and resets the
   * counters to zero.
   */
  public Duration collectDuration(Clock clock) {
    synchronized (lock) {
      // Grab the accumulated uptime and reset the counter.
      Duration duration = totalTime;
      totalTime = Duration.ZERO;

      // If it's still running, grab the current elapsed time and reset the start time to now.
      if (startTime != null) {
        Instant now = Instant.now(clock);
        Duration elapedTime = Duration.between(startTime, now);
        duration = duration.plus(elapedTime);

        startTime = now;
      }

      return duration;
    }
  }
}
