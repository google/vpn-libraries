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

import java.time.Duration;
import java.util.List;

/** Collection of metrics for how PPN is running. */
public interface PpnTelemetry {

  /**
   * Returns the cumulative duration for how long some network was available since the last time
   * telemetry was collected.
   */
  Duration networkUptime();

  /**
   * Returns the cumulative duration for how long PPN was fully connected since the last time
   * telemetry was collected.
   */
  Duration ppnConnectionUptime();

  /**
   * Returns the cumulative duration for how long the PPN VpnService was running since the last time
   * telemetry was collected.
   */
  Duration ppnServiceUptime();

  /** Returns the amount of time it took for auth to finish, every time it connected. */
  List<Duration> authLatency();

  /** Returns the amount of time it took for egress to be established, every time it connected. */
  List<Duration> egressLatency();

  /**
   * Returns the amount of time it took for oauth token to be generated during auth request, every
   * time it connected.
   */
  List<Duration> oauthLatency();

  /**
   * Returns the amount of time it took for the token to be checked by zinc during auth request,
   * every time it connected.
   */
  List<Duration> zincLatency();

  /** Returns the number of successful rekeys since the last time telemetry was collected. */
  int successfulRekeys();

  /** Returns the number of network switches since the last time telemetry was collected. */
  int networkSwitches();

  /**
   * Returns the List of all disconnection durations since the last time telemetry was collected.
   */
  List<Duration> disconnectionDurations();

  /** Returns the number of disconnections since the last time telemetry was collected */
  int disconnectionCount();
}
