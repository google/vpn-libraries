// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.neon;

import com.google.android.libraries.privacy.ppn.PpnStatus;

/** An Exception subclass with details about failures during provisioning. */
public class ProvisionException extends Exception {
  private final PpnStatus status;
  private final boolean permanent;

  public ProvisionException(PpnStatus status, boolean permanent) {
    super(
        "Unable to provision: "
            + status.getCode()
            + ": "
            + status.getMessage()
            + (permanent ? " [permanent failure]" : " [transient failure]"));
    this.status = status;
    this.permanent = permanent;
  }

  /** Returns the underlying PPN status that caused this Exception. */
  public PpnStatus getStatus() {
    return status;
  }

  /** Returns true if trying to provision again with the same argument would fail. */
  public boolean isPermanent() {
    return permanent;
  }
}
