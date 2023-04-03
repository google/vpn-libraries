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

package com.google.android.libraries.privacy.ppn.xenon;

import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;

/**
 * A callback listener for PpnNetworks. Whenever a new network is available, as deemed by Xenon, it
 * will call here so that interested services can get a callback.
 */
public interface PpnNetworkListener {
  /** All possible Reasons a PpnNetwork is unavailable. */
  public enum NetworkUnavailableReason {
    UNKNOWN,
    AIRPLANE_MODE
  }

  /**
   * Called when a Network is available.
   *
   * @param network The available PpnNetwork.
   */
  void onNetworkAvailable(PpnNetwork network);

  /**
   * Called when there is no network available. Xenon will ALWAYS try to connect to a network.
   *
   * @param reason Reason all networks are unavailable.
   */
  void onNetworkUnavailable(NetworkUnavailableReason reason);

  /**
   * Called when there is a Network Status Change.
   *
   * @param ppnNetwork The Network we are publishing the ConnectionStatus for.
   * @param connectionStatus The current ConnectionStatus of the PpnNetwork.
   */
  void onNetworkStatusChanged(PpnNetwork ppnNetwork, ConnectionStatus connectionStatus);
}
