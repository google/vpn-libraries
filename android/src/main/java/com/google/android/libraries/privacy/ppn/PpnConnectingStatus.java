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

import com.google.android.libraries.privacy.ppn.internal.ConnectingStatus;

/** Status of PPN while connecting. */
public final class PpnConnectingStatus {
  /*
   * Internally, we represent the connection status as a proto. This class wraps
   * that proto with an API for public use, so that we have the option of changing our internal
   * implementation without breaking clients.
   */

  private final boolean isBlockingTraffic;

  public PpnConnectingStatus(boolean isBlockingTraffic) {
    this.isBlockingTraffic = isBlockingTraffic;
  }

  /** Returns true if Safe Disconnect is on and PPN has connected previously. */
  public boolean isBlockingTraffic() {
    return isBlockingTraffic;
  }

  @Override
  public String toString() {
    return "ConnectingStatus{ isBlockingTraffic: " + isBlockingTraffic + "}";
  }

  /*
   * Creates a PpnConnectingStatus from its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it takes
   * an internal class, so it's not part of the supported public API.
   */
  public static PpnConnectingStatus fromProto(ConnectingStatus status) {
    return new PpnConnectingStatus(status.getIsBlockingTraffic());
  }
}
