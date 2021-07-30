// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.time.TimeSource;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link PpnSettings}. */
@RunWith(RobolectricTestRunner.class)
public final class UptimeDurationTrackerTest {

  @Test
  public void tracker_defaultsToZero() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    List<Duration> durations = uptimeDurationTracker.collectDurations(getStartClock());
    assertThat(durations).isEmpty();
  }

  @Test
  public void startAndStop_createsOneEntryInList() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock = getStartClock();
    Clock stopClock = Clock.offset(startClock, Duration.ofMillis(250));
    Clock measureClock = Clock.offset(startClock, Duration.ofMillis(500));

    uptimeDurationTracker.start(startClock);
    uptimeDurationTracker.stop(stopClock);

    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock);
    assertThat(durations).containsExactly(Duration.ofMillis(250));
  }

  @Test
  public void onlyStart_createsOneEntryInList() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock = getStartClock();
    Clock measureClock = Clock.offset(startClock, Duration.ofMillis(500));

    uptimeDurationTracker.start(startClock);
    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock);

    assertThat(durations).containsExactly(Duration.ofMillis(500));
  }

  @Test
  public void multipleStartAndStop_createsOneEntryInList() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock = getStartClock();
    Clock stopClock = Clock.offset(startClock, Duration.ofMillis(250));
    Clock measureClock = Clock.offset(startClock, Duration.ofMillis(750));

    uptimeDurationTracker.start(startClock);
    uptimeDurationTracker.stop(stopClock);
    uptimeDurationTracker.start(stopClock);
    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock);

    assertThat(durations).containsExactly(Duration.ofMillis(250), Duration.ofMillis(500)).inOrder();
  }

  @Test
  public void collect_resetsList() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock = getStartClock();
    Clock measureClock1 = Clock.offset(startClock, Duration.ofMillis(250));
    Clock measureClock2 = Clock.offset(startClock, Duration.ofMillis(750));

    uptimeDurationTracker.start(startClock);
    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock1);
    assertThat(durations).containsExactly(Duration.ofMillis(250));

    durations = uptimeDurationTracker.collectDurations(measureClock2);
    assertThat(durations).containsExactly(Duration.ofMillis(500));
  }

  @Test
  public void startTwice_isNoOp() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock1 = getStartClock();
    Clock startClock2 = Clock.offset(startClock1, Duration.ofMillis(250));
    Clock measureClock = Clock.offset(startClock1, Duration.ofMillis(500));

    uptimeDurationTracker.start(startClock1);
    uptimeDurationTracker.start(startClock2);
    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock);

    assertThat(durations).containsExactly(Duration.ofMillis(500));
  }

  @Test
  public void stopTwice_isNoOp() {
    UptimeDurationTracker uptimeDurationTracker = new UptimeDurationTracker();
    Clock startClock = getStartClock();
    Clock stopClock1 = Clock.offset(startClock, Duration.ofMillis(250));
    Clock stopClock2 = Clock.offset(startClock, Duration.ofMillis(500));
    Clock measureClock = Clock.offset(startClock, Duration.ofMillis(750));

    uptimeDurationTracker.start(startClock);
    uptimeDurationTracker.stop(stopClock1);
    uptimeDurationTracker.stop(stopClock2);
    List<Duration> durations = uptimeDurationTracker.collectDurations(measureClock);

    assertThat(durations).containsExactly(Duration.ofMillis(250));
  }

  /** Returns a default fixed clock to use as the starting point for tests. */
  private Clock getStartClock() {
    Instant now = TimeSource.system().now();
    return Clock.fixed(now, ZoneId.systemDefault());
  }
}
