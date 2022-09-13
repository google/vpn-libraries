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

package com.google.android.libraries.privacy.ppn;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import java.time.Duration;
import java.util.List;

/** Collection of metrics for how PPN is running. */
@AutoValue
public abstract class PpnTelemetry {

  /**
   * Returns the cumulative duration for how long some network was available since the last time
   * telemetry was collected.
   */
  public abstract Duration networkUptime();

  /**
   * Returns the cumulative duration for how long PPN was fully connected since the last time
   * telemetry was collected.
   */
  public abstract Duration ppnConnectionUptime();

  /**
   * Returns the cumulative duration for how long the PPN VpnService was running since the last time
   * telemetry was collected.
   */
  public abstract Duration ppnServiceUptime();

  /** Returns the amount of time it took for auth to finish, every time it connected. */
  public abstract ImmutableList<Duration> authLatency();

  /** Returns the amount of time it took for egress to be established, every time it connected. */
  public abstract ImmutableList<Duration> egressLatency();

  /**
   * Returns the amount of time it took for oauth token to be generated during auth request, every
   * time it connected.
   */
  public abstract ImmutableList<Duration> oauthLatency();

  /**
   * Returns the amount of time it took for the token to be checked by zinc during auth request,
   * every time it connected.
   */
  public abstract ImmutableList<Duration> zincLatency();

  /** Returns the number of successful rekeys since the last time telemetry was collected. */
  public abstract int successfulRekeys();

  /** Returns the number of network switches since the last time telemetry was collected. */
  public abstract int networkSwitches();

  /**
   * Returns the List of all disconnection durations since the last time telemetry was collected.
   */
  public abstract ImmutableList<Duration> disconnectionDurations();

  /** Returns the number of disconnections since the last time telemetry was collected */
  public abstract int disconnectionCount();

  public static Builder builder() {
    // Assign default values for optional fields here.
    return new AutoValue_PpnTelemetry.Builder()
        .setNetworkUptime(Duration.ZERO)
        .setPpnConnectionUptime(Duration.ZERO)
        .setPpnServiceUptime(Duration.ZERO)
        .setAuthLatency(ImmutableList.of())
        .setOauthLatency(ImmutableList.of())
        .setZincLatency(ImmutableList.of())
        .setEgressLatency(ImmutableList.of())
        .setDisconnectionDurations(ImmutableList.of())
        .setNetworkSwitches(0)
        .setSuccessfulRekeys(0)
        .setDisconnectionCount(0);
  }

  /** Simple Builder for PpnTelemetry. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setNetworkUptime(Duration value);

    public abstract Builder setPpnConnectionUptime(Duration value);

    public abstract Builder setPpnServiceUptime(Duration value);

    public abstract Builder setAuthLatency(List<Duration> value);

    public abstract Builder setOauthLatency(List<Duration> value);

    public abstract Builder setZincLatency(List<Duration> value);

    public abstract Builder setEgressLatency(List<Duration> value);

    public abstract Builder setDisconnectionDurations(List<Duration> value);

    public abstract Builder setSuccessfulRekeys(int value);

    public abstract Builder setNetworkSwitches(int value);

    public abstract Builder setDisconnectionCount(int value);

    public abstract PpnTelemetry build();
  }
}
