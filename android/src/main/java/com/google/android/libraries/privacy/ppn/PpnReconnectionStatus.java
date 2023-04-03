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

import com.google.android.libraries.privacy.ppn.internal.ReconnectionStatus;
import java.time.Duration;

/** Status for the time until PPN's next reconnection attempt. */
public class PpnReconnectionStatus {
  private final boolean isBlockingTraffic;
  private final boolean hasAvailableNetworks;
  private final Duration timeToReconnect;

  /** Construct a PpnReconnectStatus with a Java duration. */
  public PpnReconnectionStatus(
      Duration timeToReconnect, boolean isBlockingTraffic, boolean hasAvailableNetworks) {
    this.isBlockingTraffic = isBlockingTraffic;
    this.hasAvailableNetworks = hasAvailableNetworks;
    this.timeToReconnect = timeToReconnect;
  }

  /** Returns true if Safe Disconnect is on and PPN has connected previously. */
  public boolean isBlockingTraffic() {
    return isBlockingTraffic;
  }

  /** Returns false if Airplane Mode is on, or if no networks are available. */
  public boolean hasAvailableNetworks() {
    return hasAvailableNetworks;
  }

  /** Returns the time until Krypton's next reconnection attempt, as a Java duration. */
  public Duration getTimeToReconnect() {
    return this.timeToReconnect;
  }

  @Override
  public String toString() {
    return "ReconnectionStatus{ isBlockingTraffic: "
        + isBlockingTraffic
        + ", hasAvailableNetworks: "
        + hasAvailableNetworks
        + ", timeToReconnect: "
        + timeToReconnect
        + " }";
  }

  /*
   * Creates a PpnReconnectionStatus from its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it takes
   * an internal class, so it's not part of the supported public API.
   */
  public static PpnReconnectionStatus fromProto(ReconnectionStatus status) {
    Duration timeToReconnect =
        Duration.ofSeconds(
            status.getTimeToReconnect().getSeconds(), status.getTimeToReconnect().getNanos());
    return new PpnReconnectionStatus(
        timeToReconnect, status.getIsBlockingTraffic(), status.getHasAvailableNetworks());
  }
}
