// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
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
    assertThat(telemetry.disconnectionDurations()).isEmpty();
    assertThat(telemetry.disconnectionCount()).isEqualTo(0);
  }

  @Test
  public void collect_returnsCorrectValues() {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);

    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyNetworkUnavailable(telemetryManager, initClock, 5);
    notifyStopped(telemetryManager, initClock, 6);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 7);

    verify(mockClock, times(7)).getClock();
    verifyNoMoreInteractions(mockClock);
    assertThat(telemetry.ppnServiceUptime().toMillis()).isEqualTo(5);
    assertThat(telemetry.ppnConnectionUptime().toMillis()).isEqualTo(1);
    assertThat(telemetry.networkUptime().toMillis()).isEqualTo(3);
    assertThat(telemetry.disconnectionDurations()).hasSize(1);
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
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

  @Test
  public void disconnectionFollowedByReconnection_collectsOneDisconnection() throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyConnected(telemetryManager, initClock, 5);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 7);

    assertThat(telemetry.disconnectionDurations()).containsExactly(Duration.ofMillis(1));
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
  }

  @Test
  public void disconnectionFollowedByNetworkLossAndReconnect_collectsTwoDisconnections()
      throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyNetworkUnavailable(telemetryManager, initClock, 5);
    notifyNetworkAvailable(telemetryManager, initClock, 6);
    notifyConnected(telemetryManager, initClock, 8);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 9);

    assertThat(telemetry.disconnectionDurations())
        .containsExactly(Duration.ofMillis(1), Duration.ofMillis(2))
        .inOrder();
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
  }

  @Test
  public void disconnectionFollowedbyMultipleNetworkLossesAndReconnect_collectsThreeDisconnections()
      throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyNetworkUnavailable(telemetryManager, initClock, 5);
    notifyNetworkAvailable(telemetryManager, initClock, 6);
    notifyNetworkUnavailable(telemetryManager, initClock, 7);
    notifyNetworkAvailable(telemetryManager, initClock, 8);
    notifyConnected(telemetryManager, initClock, 10);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 11);

    assertThat(telemetry.disconnectionDurations())
        .containsExactly(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofMillis(2))
        .inOrder();
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
  }

  @Test
  public void disconnectionFollowedByStop_collectsOneDisconnection() throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyStopped(telemetryManager, initClock, 5);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 11);

    assertThat(telemetry.disconnectionDurations()).containsExactly(Duration.ofMillis(1));
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
  }

  @Test
  public void disconnectionFollowedByNetworkLossAndStop_collectsOneDisconnection()
      throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyDisconnected(telemetryManager, initClock, 4);
    notifyNetworkUnavailable(telemetryManager, initClock, 6);
    notifyStopped(telemetryManager, initClock, 7);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 11);

    assertThat(telemetry.disconnectionDurations()).containsExactly(Duration.ofMillis(2));
    assertThat(telemetry.disconnectionCount()).isEqualTo(1);
  }

  @Test
  public void noDisconnection_shouldNotCollectDisconnectionSpan() throws Exception {
    PpnTelemetryManager telemetryManager = new PpnTelemetryManager(mockClock);
    Clock initClock = getStartClock();

    notifyStarted(telemetryManager, initClock, 1);
    notifyNetworkAvailable(telemetryManager, initClock, 2);
    notifyConnected(telemetryManager, initClock, 3);
    notifyNetworkUnavailable(telemetryManager, initClock, 6);
    notifyStopped(telemetryManager, initClock, 7);
    PpnTelemetry telemetry = collect(telemetryManager, initClock, 11);

    assertThat(telemetry.disconnectionDurations()).isEmpty();
    assertThat(telemetry.disconnectionCount()).isEqualTo(0);
  }

  private void notifyStarted(PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock startClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(startClock);
    telemetryManager.notifyStarted();
  }

  private void notifyStopped(PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock stopClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(stopClock);
    telemetryManager.notifyStopped();
  }

  private void notifyNetworkAvailable(
      PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock networkAvailableClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(networkAvailableClock);
    telemetryManager.notifyNetworkAvailable();
  }

  private void notifyNetworkUnavailable(
      PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock networkUnavailableClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(networkUnavailableClock);
    telemetryManager.notifyNetworkUnavailable();
  }

  private void notifyConnected(PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock connectClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(connectClock);
    telemetryManager.notifyConnected();
  }

  private void notifyDisconnected(
      PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock disconnectClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(disconnectClock);
    telemetryManager.notifyDisconnected();
  }

  private PpnTelemetry collect(PpnTelemetryManager telemetryManager, Clock initClock, int millis) {
    Clock measureClock = Clock.offset(initClock, Duration.ofMillis(millis));
    when(mockClock.getClock()).thenReturn(measureClock);
    return telemetryManager.collect(null);
  }

  /** Returns a default fixed clock to use as the starting point for tests. */
  private Clock getStartClock() {
    Instant now = Instant.now();
    return Clock.fixed(now, ZoneId.systemDefault());
  }

}
