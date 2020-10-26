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

import static com.google.common.truth.Truth.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link PpnSettings}. */
@RunWith(RobolectricTestRunner.class)
public class UptimeTrackerTest {

  @Test
  public void tracker_defaultsToZero() {
    UptimeTracker tracker = new UptimeTracker();

    Duration duration = tracker.collectDuration(getStartClock());

    assertThat(duration.toMillis()).isEqualTo(0);
  }

  @Test
  public void startAndStop_hasDuration() {
    UptimeTracker tracker = new UptimeTracker();
    Clock startClock = getStartClock();
    Clock stopClock = Clock.offset(startClock, Duration.ofMillis(500));
    Clock measureClock = Clock.offset(stopClock, Duration.ofMillis(500));

    tracker.start(startClock);
    tracker.stop(stopClock);
    Duration duration = tracker.collectDuration(measureClock);

    assertThat(duration.toMillis()).isEqualTo(500);
  }

  @Test
  public void start_hasDuration() {
    UptimeTracker tracker = new UptimeTracker();
    Clock startClock = getStartClock();
    Clock measureClock = Clock.offset(startClock, Duration.ofMillis(500));

    tracker.start(startClock);
    Duration duration = tracker.collectDuration(measureClock);
    assertThat(duration.toMillis()).isEqualTo(500);
  }

  @Test
  public void collect_resetsDuration() {
    UptimeTracker tracker = new UptimeTracker();
    Clock startClock = getStartClock();
    Clock measureClock1 = Clock.offset(startClock, Duration.ofMillis(500));
    Clock measureClock2 = Clock.offset(measureClock1, Duration.ofMillis(750));

    tracker.start(startClock);
    Duration duration = tracker.collectDuration(measureClock1);
    assertThat(duration.toMillis()).isEqualTo(500);

    duration = tracker.collectDuration(measureClock2);
    assertThat(duration.toMillis()).isEqualTo(750);
  }

  @Test
  public void startTwice_isNoOp() {
    UptimeTracker tracker = new UptimeTracker();
    Clock startClock1 = getStartClock();
    Clock startClock2 = Clock.offset(startClock1, Duration.ofMillis(250));
    Clock measureClock = Clock.offset(startClock1, Duration.ofMillis(500));

    tracker.start(startClock1);
    tracker.start(startClock2);
    Duration duration = tracker.collectDuration(measureClock);
    assertThat(duration.toMillis()).isEqualTo(500);
  }

  @Test
  public void stopTwice_isNoOp() {
    UptimeTracker tracker = new UptimeTracker();
    Clock startClock = getStartClock();
    Clock stopClock1 = Clock.offset(startClock, Duration.ofMillis(500));
    Clock stopClock2 = Clock.offset(startClock, Duration.ofMillis(750));
    Clock measureClock = Clock.offset(stopClock2, Duration.ofMillis(2000));

    tracker.start(startClock);
    tracker.stop(stopClock1);
    tracker.stop(stopClock2);
    Duration duration = tracker.collectDuration(measureClock);

    assertThat(duration.toMillis()).isEqualTo(500);
  }

  @Test
  public void uptime_isCumulative() {
    UptimeTracker tracker = new UptimeTracker();
    Clock initClock = getStartClock();

    Clock startClock1 = Clock.offset(initClock, Duration.ofMillis(100));
    Clock stopClock1 = Clock.offset(startClock1, Duration.ofMillis(1));

    Clock startClock2 = Clock.offset(stopClock1, Duration.ofMillis(200));
    Clock stopClock2 = Clock.offset(startClock2, Duration.ofMillis(2));

    Clock startClock3 = Clock.offset(stopClock1, Duration.ofMillis(300));
    Clock measureClock = Clock.offset(startClock3, Duration.ofMillis(3));

    tracker.start(startClock1);
    tracker.stop(stopClock1);

    tracker.start(startClock2);
    tracker.stop(stopClock2);

    tracker.start(startClock3);
    Duration duration = tracker.collectDuration(measureClock);

    assertThat(duration.toMillis()).isEqualTo(6);
  }

  /** Returns a default fixed clock to use as the starting point for tests. */
  private Clock getStartClock() {
    Instant now = Instant.now();
    return Clock.fixed(now, ZoneId.systemDefault());
  }
}
