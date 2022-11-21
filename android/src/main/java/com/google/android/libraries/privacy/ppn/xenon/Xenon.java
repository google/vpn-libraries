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

package com.google.android.libraries.privacy.ppn.xenon;

import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.errorprone.annotations.ResultIgnorabilityUnspecified;
import java.util.List;
import org.json.JSONObject;

/**
 * Xenon is the service that is responsible for handling which Network to use in PPN VPN. It will
 * pick the best available network and switch networks when deemed appropriate.
 */
public interface Xenon {

  /**
   * Starts a Network connection. Should be called when a PPN VPN session is started.
   *
   * @throws PpnException if the service cannot be started for any reason.
   */
  void start() throws PpnException;

  /**
   * Stops a Network connection. Should be called when a PPN VPN session is stopped.
   *
   * @throws PpnException if the service cannot be started for any reason.
   */
  void stop() throws PpnException;

  /** Returns a network with the given ID, or null if none is available. */
  @Nullable
  PpnNetwork getNetwork(long id);

  /**
   * Deprioritizes the Network passed in by moving it from the available network to the pending
   * network. Xenon will attempt to use this network again as according to its evaluations.
   *
   * @return whether the network was successfully deprioritized. It will not be deprioritized if the
   *     passed in Network does not exist in the available map or if this network is the only
   *     available network.
   */
  @ResultIgnorabilityUnspecified
  boolean deprioritize(NetworkInfo networkInfo);

  /** Reevaluates all the available networks to get the best network to use. */
  void reevaluateNetworks();

  /** Returns all of Xenon's available networks, including the active network. */
  List<PpnNetwork> getAvailableNetworks();

  /** Returns useful debug info for inspecting the state of Xenon. */
  JSONObject getDebugJson();
}
