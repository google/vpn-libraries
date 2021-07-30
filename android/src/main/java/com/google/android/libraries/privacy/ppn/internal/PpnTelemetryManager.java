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

import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.PpnTelemetry;
import com.google.android.libraries.privacy.ppn.krypton.Krypton;
import com.google.android.libraries.privacy.ppn.krypton.KryptonException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/** Singleton responsible for tracking telemetry data about how well PPN is running. */
class PpnTelemetryManager {
  private static final String TAG = "PpnTelemetryManager";

  private final UptimeTracker serviceTracker = new UptimeTracker();
  private final UptimeTracker connectionTracker = new UptimeTracker();
  private final UptimeTracker networkTracker = new UptimeTracker();
  private final UptimeDurationTracker disconnectionDurationTracker = new UptimeDurationTracker();
  private final AtomicInteger disconnectionCount = new AtomicInteger();

  private final ClockProvider clockProvider;

  // Track the state to double-check events are consistent.
  AtomicBoolean running = new AtomicBoolean(false);
  AtomicBoolean connected = new AtomicBoolean(false);
  // !Connected can't be used as disconnected as Connected and Disconnected both will be false
  // before the first time PPN has connected.
  AtomicBoolean disconnected = new AtomicBoolean(false);

  public PpnTelemetryManager(ClockProvider clockProvider) {
    this.clockProvider = clockProvider;
  }

  public PpnTelemetryManager(Clock clock) {
    this(() -> clock);
  }

  public PpnTelemetryManager() {
    this(Clock.systemUTC());
  }

  /** Should be called when the PPN service starts. */
  public void notifyStarted() {
    running.set(true);
    serviceTracker.start(clockProvider.getClock());
  }

  /** Should be called when the PPN service stops. */
  public void notifyStopped() {
    if (connected.compareAndSet(true, false)) {
      Log.e(
          TAG,
          "PPN was marked as stopped, even though it's still connected. Marking disconnected.");
    }
    running.set(false);
    Clock clock = clockProvider.getClock();
    disconnectionDurationTracker.stop(clock);
    serviceTracker.stop(clock);
  }

  /** Should be called when PPN connects. */
  public void notifyConnected() {
    Clock clock = clockProvider.getClock();
    if (!running.get()) {
      Log.e(TAG, "PPN was marked as connected even though the service is not running.");
    }
    connected.set(true);
    connectionTracker.start(clock);
    disconnectionDurationTracker.stop(clock);
    disconnected.set(false);
  }

  /** Should be called when PPN disconnects. */
  public void notifyDisconnected() {
    if (disconnected.compareAndSet(false, true)) {
      disconnectionCount.incrementAndGet();
    }
    connected.set(false);
    Clock clock = clockProvider.getClock();
    connectionTracker.stop(clock);
    disconnectionDurationTracker.start(clock);
  }

  /** Should be called when any network is available, according to Xenon. */
  public void notifyNetworkAvailable() {
    if (!running.get()) {
      Log.e(TAG, "PPN was marked as network available, but not marked as running.");
    }
    Clock clock = clockProvider.getClock();
    if (disconnected.get()) {
      disconnectionDurationTracker.start(clock);
    }
    networkTracker.start(clock);
  }

  /** Should be called when no network is available, according to Xenon. */
  public void notifyNetworkUnavailable() {
    if (!running.get()) {
      Log.e(TAG, "PPN was marked as network unavailable, but not marked as running.");
    }
    Clock clock = clockProvider.getClock();
    disconnectionDurationTracker.stop(clock);
    networkTracker.stop(clock);
  }

  /**
   * Returns a collection of the metrics since the last time collect was called, and resets them.
   */
  public PpnTelemetry collect(@Nullable Krypton krypton) {
    Clock clock = clockProvider.getClock();

    KryptonTelemetry kryptonTelemetry = null;
    if (krypton != null) {
      try {
        kryptonTelemetry = krypton.collectTelemetry();
      } catch (KryptonException e) {
        Log.e(TAG, "Unable to collect telemetry from Krypton.", e);
      }
    }
    PpnTelemetryImpl.Builder builder =
        PpnTelemetryImpl.builder()
            .setPpnServiceUptime(serviceTracker.collectDuration(clock))
            .setPpnConnectionUptime(connectionTracker.collectDuration(clock))
            .setNetworkUptime(networkTracker.collectDuration(clock))
            .setDisconnectionDurations(disconnectionDurationTracker.collectDurations(clock))
            .setDisconnectionCount(disconnectionCount.getAndSet(0));

    if (kryptonTelemetry != null) {
      builder =
          builder
              .setAuthLatency(convertDurationList(kryptonTelemetry.getAuthLatencyList()))
              .setOauthLatency(convertDurationList(kryptonTelemetry.getOauthLatencyList()))
              .setZincLatency(convertDurationList(kryptonTelemetry.getZincLatencyList()))
              .setEgressLatency(convertDurationList(kryptonTelemetry.getEgressLatencyList()))
              .setSuccessfulRekeys(kryptonTelemetry.getSuccessfulRekeys())
              .setNetworkSwitches(kryptonTelemetry.getNetworkSwitches());
    }

    return builder.build();
  }

  private static List<Duration> convertDurationList(List<com.google.protobuf.Duration> list) {
    return list.stream().map(PpnTelemetryManager::convertDuration).collect(Collectors.toList());
  }

  private static Duration convertDuration(com.google.protobuf.Duration duration) {
    return Duration.ofSeconds(duration.getSeconds(), duration.getNanos());
  }
}
