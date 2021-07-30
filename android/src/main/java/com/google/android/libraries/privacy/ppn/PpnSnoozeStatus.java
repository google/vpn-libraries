// Copyright 2021 Google LLC
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

import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;
import com.google.protobuf.Timestamp;
import java.time.Instant;

/** Information about a PPN session's disconnection. */
public class PpnSnoozeStatus {

  private final Instant snoozeEndTime;

  public PpnSnoozeStatus(Instant snoozeEndTime) {
    this.snoozeEndTime = snoozeEndTime;
  }

  public Instant getSnoozeEndTime() {
    return snoozeEndTime;
  }

  @Override
  public String toString() {
    return "SnoozeStatus{ " + "snoozeEndTime: " + snoozeEndTime + " }";
  }

  /*
   * Creates a PpnSnoozeStatus from its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it takes
   * an internal class, so it's not part of the supported public API.
   */
  public static PpnSnoozeStatus fromProto(SnoozeStatus status) {
    Timestamp snoozeEndTime = status.getSnoozeEndTime();
    return new PpnSnoozeStatus(
        Instant.ofEpochSecond(snoozeEndTime.getSeconds(), snoozeEndTime.getNanos()));
  }
}
