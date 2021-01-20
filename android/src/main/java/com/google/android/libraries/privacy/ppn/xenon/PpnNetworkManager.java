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

import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.Task;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import java.util.List;
import org.json.JSONObject;

/**
 * PPN Network Manager is the core service responsible for keeping track of the available networks.
 * It includes the core logic for handling when a network is available, lost, and changed.
 */
public interface PpnNetworkManager {

  /** Starts Network Requests and sets up the callback listeners with Android system. */
  void startNetworkRequests();

  /** Stops all existing Network Requests. */
  void stopNetworkRequests();

  /**
   * Handles the Network onAvailable callback. Includes adding the new PpnNetwork and alerting the
   * change if deemed appropriate by the PpnNetworkSelector.
   *
   * <p>Returns a Task that completes when all of the work spawned off by this event has completed.
   * The result of the Task indicates whether this event caused the network to be marked as
   * available.
   */
  Task<Boolean> handleNetworkAvailable(PpnNetwork ppnNetwork);

  /**
   * Handles the Network onLost callback. Includes removing the PpnNetwork, doing storage
   * bookkeeping, and alerting if no networks are available.
   */
  void handleNetworkLost(PpnNetwork ppnNetwork);

  /**
   * Handles the Network onCapabilitiesChanged callback. Includes figuring out whether the changes
   * deems the Network still available and switching over to a different Network is necessary.
   *
   * <p>Returns a Task that completes when all of the work spawned off by this event has completed.
   * The result of the Task indicates whether this event caused the network to be marked as
   * available.
   */
  Task<Boolean> handleNetworkCapabilitiesChanged(
      PpnNetwork ppnNetwork, NetworkCapabilities networkCapabilities);

  /**
   * Handles the Network onLinkPropertiesChanged callback. Includes examining the new LinkProperty
   * and deciding whether to switch the network or not.
   *
   * <p>Returns a Task that completes when all of the work spawned off by this event has completed.
   * The result of the Task indicates whether this event caused the network to be marked as
   * available.
   */
  Task<Boolean> handleNetworkLinkPropertiesChanged(
      PpnNetwork ppnNetwork, LinkProperties linkProperties);

  /**
   * Returns all the available networks that Xenon is tracking. This includes the current active
   * network.
   *
   * <p>Note: The List is NOT ordered in any particular fashion. You cannot assume the first element
   * is the best network.
   */
  List<PpnNetwork> getAllNetworks();

  /** Returns the network with the given ID, or null if none is available. */
  @Nullable
  PpnNetwork getPpnNetwork(long networkId);

  /**
   * Deprioritizes the Network passed in by moving it from the available network to the pending
   * network. Xenon will attempt to use this network again as according to its evaluations.
   *
   * @return whether the network was successfully deprioritized. It will not be deprioritized if the
   *     passed in Network does not exist in the available map or if this network is the only
   *     available network.
   */
  boolean deprioritize(NetworkInfo networkInfo);

  /**
   * Xenon will reevaluate all the available network and pick the best network to use. If the new
   * best network is different, it will publish to the listeners as usual.
   */
  void reevaluateNetworks();

  /** Returns useful debug info for inspecting the state of Xenon. */
  public JSONObject getDebugJson();
}
