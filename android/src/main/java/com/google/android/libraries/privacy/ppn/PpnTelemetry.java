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

  /** Returns the number successful network switches since the last time telemetry was collected. */
  public abstract int successfulNetworkSwitches();

  /** Returns the duration from when a network switch begins and when it is found successful. */
  public abstract ImmutableList<Duration> networkSwitchLatency();

  /***
   * Returns the number of times the attempts control plane negotiations upon Session start.
   */
  public abstract int controlPlaneAttempts();

  /***
   * Returns the number of times the client successfully completes control plane negotiations during
   * Session start.
   */
  public abstract int controlPlaneSuccesses();

  /** Returns the duration from start of a Session until the control plane is connected. */
  public abstract ImmutableList<Duration> controlPlaneSuccessLatency();

  /* Returns the duration from start of Session until a control plane failure is encountered. */
  public abstract ImmutableList<Duration> controlPlaneFailureLatency();

  /***
   * Returns the number of times the client attempts to connect the datapath.
   */
  public abstract int dataPlaneConnectingAttempts();

  /***
   * Returns the number of times the client successfully connects a datapath.
   */
  public abstract int dataPlaneConnectingSuccesses();

  /***
   * Returns the amount of time it took from the start of datapath connecting until fully
   * connected.
   */
  public abstract ImmutableList<Duration> dataPlaneConnectingLatency();

  /* Returns the number of times the client attempts a health check. */
  public abstract int healthCheckAttempts();

  /* Returns the number of times the client health check attempt is successful */
  public abstract int healthCheckSuccesses();

  /*
   * Returns the number of times token unblinding fails in Krypton, leading to an authentication
   * failure
   */
  public abstract int tokenUnblindFailureCount();

  /* Returns the number of times Android and Krypton disagree whether there is an active tunnel. */
  public abstract int tunnelDisagreementCount();

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
        .setDisconnectionCount(0)
        .setSuccessfulNetworkSwitches(0)
        .setNetworkSwitchLatency(ImmutableList.of())
        .setControlPlaneAttempts(0)
        .setControlPlaneSuccesses(0)
        .setControlPlaneSuccessLatency(ImmutableList.of())
        .setControlPlaneFailureLatency(ImmutableList.of())
        .setDataPlaneConnectingAttempts(0)
        .setDataPlaneConnectingSuccesses(0)
        .setDataPlaneConnectingLatency(ImmutableList.of())
        .setHealthCheckAttempts(0)
        .setHealthCheckSuccesses(0)
        .setTokenUnblindFailureCount(0)
        .setTunnelDisagreementCount(0);
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

    public abstract Builder setSuccessfulNetworkSwitches(int value);

    public abstract Builder setNetworkSwitchLatency(List<Duration> value);

    public abstract Builder setControlPlaneAttempts(int value);

    public abstract Builder setControlPlaneSuccesses(int value);

    public abstract Builder setControlPlaneSuccessLatency(List<Duration> value);

    public abstract Builder setControlPlaneFailureLatency(List<Duration> value);

    public abstract Builder setDataPlaneConnectingAttempts(int value);

    public abstract Builder setDataPlaneConnectingSuccesses(int value);

    public abstract Builder setDataPlaneConnectingLatency(List<Duration> value);

    public abstract Builder setHealthCheckAttempts(int value);

    public abstract Builder setHealthCheckSuccesses(int value);

    public abstract Builder setTokenUnblindFailureCount(int value);

    public abstract Builder setTunnelDisagreementCount(int value);

    public abstract PpnTelemetry build();
  }
}
