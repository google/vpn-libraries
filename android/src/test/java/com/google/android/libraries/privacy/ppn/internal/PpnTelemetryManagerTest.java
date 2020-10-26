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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.google.android.libraries.privacy.ppn.PpnTelemetry;
import com.google.android.libraries.privacy.ppn.krypton.Krypton;
import com.google.testing.mockito.Mocks;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link PpnSettings}. */
@RunWith(RobolectricTestRunner.class)
public class PpnTelemetryManagerTest {

  @Rule public Mocks mocks = new Mocks(this);

  @Mock private Krypton mockKrypton;
  @Mock private ClockProvider mockClock;

  @Test
  public void collect_defaultsToZero() {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);

    when(mockClock.getClock()).thenReturn(getStartClock());

    PpnTelemetry telemetry = telemetryManager.collect(null);

    verify(mockClock).getClock();
    verifyNoMoreInteractions(mockClock);
    assertThat(telemetry.ppnServiceUptime().toMillis()).isEqualTo(0);
    assertThat(telemetry.ppnConnectionUptime().toMillis()).isEqualTo(0);
    assertThat(telemetry.networkUptime().toMillis()).isEqualTo(0);
  }

  @Test
  public void collect_returnsCorrectValues() {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);

    Clock initClock = getStartClock();
    Clock startClock = Clock.offset(initClock, Duration.ofMillis(1));
    Clock networkAvailableClock = Clock.offset(initClock, Duration.ofMillis(2));
    Clock connectClock = Clock.offset(initClock, Duration.ofMillis(3));
    Clock disconnectClock = Clock.offset(initClock, Duration.ofMillis(4));
    Clock networkUnavailableClock = Clock.offset(initClock, Duration.ofMillis(5));
    Clock stopClock = Clock.offset(initClock, Duration.ofMillis(6));
    Clock measureClock = Clock.offset(initClock, Duration.ofMillis(7));

    when(mockClock.getClock()).thenReturn(startClock);
    telemetryManager.notifyStarted();

    when(mockClock.getClock()).thenReturn(networkAvailableClock);
    telemetryManager.notifyNetworkAvailable();

    when(mockClock.getClock()).thenReturn(connectClock);
    telemetryManager.notifyConnected();

    when(mockClock.getClock()).thenReturn(disconnectClock);
    telemetryManager.notifyDisconnected();

    when(mockClock.getClock()).thenReturn(networkUnavailableClock);
    telemetryManager.notifyNetworkUnavailable();

    when(mockClock.getClock()).thenReturn(stopClock);
    telemetryManager.notifyStopped();

    when(mockClock.getClock()).thenReturn(measureClock);
    PpnTelemetry telemetry = telemetryManager.collect(null);

    verify(mockClock, times(7)).getClock();
    verifyNoMoreInteractions(mockClock);
    assertThat(telemetry.ppnServiceUptime().toMillis()).isEqualTo(5);
    assertThat(telemetry.ppnConnectionUptime().toMillis()).isEqualTo(1);
    assertThat(telemetry.networkUptime().toMillis()).isEqualTo(3);
  }

  @Test
  public void collect_callsIntoKrypton() throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);

    KryptonTelemetry kryptonTelemetry =
        KryptonTelemetry.newBuilder().setSuccessfulRekeys(1).setNetworkSwitches(2).build();

    when(mockClock.getClock()).thenReturn(getStartClock());
    when(mockKrypton.collectTelemetry()).thenReturn(kryptonTelemetry);

    PpnTelemetry telemetry = telemetryManager.collect(mockKrypton);

    verify(mockClock).getClock();
    verify(mockKrypton).collectTelemetry();
    verifyNoMoreInteractions(mockClock);
    verifyNoMoreInteractions(mockKrypton);

    assertThat(telemetry.successfulRekeys()).isEqualTo(1);
    assertThat(telemetry.networkSwitches()).isEqualTo(2);
  }

  /** Returns a default fixed clock to use as the starting point for tests. */
  private Clock getStartClock() {
    Instant now = Instant.now();
    return Clock.fixed(now, ZoneId.systemDefault());
  }
}
