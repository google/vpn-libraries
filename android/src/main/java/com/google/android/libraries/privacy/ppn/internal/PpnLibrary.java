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

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

/**
 * PpnLibrary provides an API that the PpnVpnService can use to communicate with the PPN library
 * running in the app's memory space. For now, this uses a singleton instance.
 */
public class PpnLibrary {
  @Nullable private static volatile PpnLibrary instance;

  // The PPN library instance to connect to.
  private final PpnImpl ppn;

  private PpnLibrary(PpnImpl ppn) {
    this.ppn = ppn;
  }

  /**
   * Sets the Ppn singleton instance to be used by the PPN Service code. This should be called
   * before Application#onCreate() has terminated.
   */
  public static void init(PpnImpl ppn) {
    if (instance != null) {
      throw new IllegalStateException("PpnLibrary.init() was called more than once.");
    }
    instance = new PpnLibrary(ppn);
  }

  /**
   * Returns the singleton instance of Ppn. This should only be called after Application#onCreate().
   */
  public static PpnImpl getPpn() {
    if (instance == null) {
      throw new IllegalStateException("PpnLibrary.init() was not called.");
    }
    return instance.ppn;
  }

  /** Resets the registered PPN singleton. */
  @VisibleForTesting
  public static void clear() {
    instance = null;
  }
}
