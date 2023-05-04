// Copyright 2021 Google LLC
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

import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;

/** Information about a PPN session's disconnection. */
public class PpnDisconnectionStatus {
  private final PpnStatus reason;
  private final boolean isBlockingTraffic;
  private final boolean hasAvailableNetworks;

  public PpnDisconnectionStatus(
      PpnStatus reason, boolean isBlockingTraffic, boolean hasAvailableNetworks) {
    this.reason = reason;
    this.isBlockingTraffic = isBlockingTraffic;
    this.hasAvailableNetworks = hasAvailableNetworks;
  }

  /** Returns the reason that PPN disconnected. */
  public PpnStatus getReason() {
    return reason;
  }

  /** Returns true if Safe Disconnect is on and PPN has connected previously. */
  public boolean isBlockingTraffic() {
    return isBlockingTraffic;
  }

  /** Returns false if Airplane Mode is on, or if no networks are available. */
  public boolean hasAvailableNetworks() {
    return hasAvailableNetworks;
  }

  @Override
  public String toString() {
    return "DisconnectionStatus{ reason: "
        + reason
        + ", isBlockingTraffic: "
        + isBlockingTraffic
        + ", hasAvailableNetworks: "
        + hasAvailableNetworks
        + " }";
  }

  /*
   * Creates a PpnDisconnectionStatus from its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it takes
   * an internal class, so it's not part of the supported public API.
   */
  public static PpnDisconnectionStatus fromProto(DisconnectionStatus status) {
    PpnStatus reason = new PpnStatus.Builder(status.getCode(), status.getMessage()).build();
    return new PpnDisconnectionStatus(
        reason, status.getIsBlockingTraffic(), status.getHasAvailableNetworks());
  }
}
