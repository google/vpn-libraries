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

package com.google.android.libraries.privacy.ppn.xenon.impl.v2;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus.ConnectionQuality;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkCallback;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener.NetworkUnavailableReason;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkManager;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkSelector;
import com.google.common.collect.ImmutableList;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import org.json.JSONObject;

/**
 * PpnNetworkManagerImpl is the impl of the core service responsible for keeping track of the
 * available networks. It includes the core logic for handling when a network is available, lost,
 * and changed.
 */
final class PpnNetworkManagerImpl
    implements PpnNetworkManager, PpnNetworkValidator.NetworkValidationListener {
  private static final String TAG = "PpnNetworkManagerImpl";

  private final Context context;
  // Mutex that guards the networks and the callbacks.
  private final Object lock = new Object();

  // Variable that ensures that we only evaluate networks once at a time.
  private boolean isEvaluatingNetworks = false;

  @Nullable private PpnNetworkCallback wifiCallback;
  @Nullable private PpnNetworkCallback cellularCallback;

  private final Handler mainHandler = new Handler(Looper.getMainLooper());
  private final PpnNetworkListener listener;
  private final PpnNetworkSelector ppnNetworkSelector;
  private final PpnNetworkValidator ppnNetworkValidator;

  // Set to keep track of the pending available networks to add to our available list.
  // Every network is added to this set when it is first discovered.
  // If it is a WiFi network, then we start an async check of whether we have connectivity. If that
  // succeeds and the network is still pending, we promote it to "available".
  // If it is a cell network, then we wait for a link address to become available. Once it is, we
  // start the connectivity check, the same as with a WiFi network.
  private final HashSet<PpnNetwork> pendingNetworks;

  // The set of networks that we think are in good working order, and may be used by PPN.
  // Networks are removed from this list when Android reports them as gone.
  // If deprioritize is called, a network can be demoted from this list back to pending.
  private final HashSet<PpnNetwork> availableNetworks;

  // Current active Network used. Generally, this is the "best" considered Network.
  @Nullable private PpnNetwork activeNetwork;
  // The current known ConnectionQuality associated with the active network.
  private ConnectionQuality connectionQuality = ConnectionQuality.UNKNOWN_QUALITY;

  public static final NetworkRequest WIFI_NETWORK_REQUEST =
      new NetworkRequest.Builder()
          // Must have Internet access
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          // And not be another VPN
          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          // And only be on the Wifi interface
          .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
          .build();

  public static final NetworkRequest CELLULAR_NETWORK_REQUEST =
      new NetworkRequest.Builder()
          // Must have Internet access
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          // And not be another VPN
          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          // And only be on the cellular interface
          .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
          .build();

  public PpnNetworkManagerImpl(
      Context context,
      PpnNetworkListener listener,
      HttpFetcher httpFetcher,
      PpnOptions ppnOptions) {
    this.context = context;
    this.listener = listener;
    this.availableNetworks = new HashSet<>();
    this.pendingNetworks = new HashSet<>();
    this.ppnNetworkSelector = new PpnNetworkSelectorImpl(context);
    this.ppnNetworkValidator = new PpnNetworkValidator(context, this, httpFetcher, ppnOptions);
  }

  @Override
  public ImmutableList<PpnNetwork> getAllNetworks() {
    synchronized (lock) {
      return ImmutableList.copyOf(availableNetworks);
    }
  }

  @Override
  public void startNetworkRequests() {
    synchronized (lock) {
      Log.w(TAG, "Starting NetworkRequests");

      // Release any existing callback if there are any.
      releaseAllNetworkRequests();

      // Reset the state for any pending networks.
      this.pendingNetworks.clear();

      // Initialize the network callbacks.
      this.wifiCallback = new PpnNetworkCallback(this, NetworkType.WIFI, WIFI_NETWORK_REQUEST);
      this.cellularCallback =
          new PpnNetworkCallback(this, NetworkType.CELLULAR, CELLULAR_NETWORK_REQUEST);

      // Request networks and pass corresponding callbacks.
      requestNetwork(wifiCallback);
      requestNetwork(cellularCallback);
    }
  }

  @Override
  public void stopNetworkRequests() {
    synchronized (lock) {
      Log.w(TAG, "Stopping NetworkRequests");
      ppnNetworkValidator.clearAllNetworkValidation();
      pendingNetworks.clear();
      releaseAllNetworkRequests();
      clearState();
    }
  }

  @Override
  public Task<Boolean> handleNetworkAvailable(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      Log.w(TAG, String.format("Network Available with network: %s", ppnNetwork));

      // We do not need to verify that the network has been lost. We're guaranteed a callback to
      // onCapabilitiesChanged.

      pendingNetworks.add(ppnNetwork);

      // For cellular networks, we cannot consider it as an available network until it has
      // established an IP Address, so there's no need to actively do anything. The link properties
      // change will trigger further action.
      if (ppnNetwork.getNetworkType() == NetworkType.CELLULAR) {
        this.printAvailableNetworkMap();
        return Tasks.forResult(false);
      }

      // For WiFi networks, go ahead and start network validation.
      return ppnNetworkValidator.validateNetwork(ppnNetwork);
    }
  }

  @Override
  public void handleNetworkLost(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      Log.w(TAG, String.format("Network Lost with network: %s", ppnNetwork));

      ppnNetworkValidator.clearNetworkValidation(ppnNetwork);

      // If the lost network is pending, remove it.
      if (pendingNetworks.contains(ppnNetwork)) {
        pendingNetworks.remove(ppnNetwork);
        return;
      }

      // If lost network is not tracked, ignore.
      if (!containsPpnNetwork(ppnNetwork)) {
        return;
      }
      removeNetwork(ppnNetwork);

      this.printAvailableNetworkMap();
    }
  }

  @Override
  public Task<Boolean> handleNetworkCapabilitiesChanged(
      PpnNetwork ppnNetwork, NetworkCapabilities networkCapabilities) {
    synchronized (lock) {
      Log.w(
          TAG,
          String.format(
              "onCapabilitiesChanged for network: %s with networkCapabilities: %s",
              ppnNetwork, networkCapabilities));

      if (networkCapabilities == null) {
        // Network was lost. No action here as it should be handled by onLost NetworkCallback.
        return Tasks.forResult(false);
      }

      // Validate the current Network. If it fails away of these conditions, remove the network.
      if (!networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          || !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)) {
        Log.w(TAG, "onCapabilitiesChanged. Removing Network as Capability is not valid");
        removeNetwork(ppnNetwork);
        return Tasks.forResult(false);
      }

      return ppnNetworkValidator
          .validateNetwork(ppnNetwork)
          .continueWithTask(
              (task) -> {
                updateConnectionQuality(ppnNetwork, networkCapabilities);
                return task;
              });
    }
  }

  /**
   * Checks the connection quality of the given network, if it is the active network, and emits an
   * event to update listeners if the connection quality has changed.
   */
  public void updateConnectionQuality(
      PpnNetwork ppnNetwork, NetworkCapabilities networkCapabilities) {
    synchronized (lock) {
      // If the current activeNetwork has a different ConnectionQuality, we need to update and
      // publish this change to the listener. We currently only support tracking the
      // ConnectionQuality of the activeNetwork because we handle the ConnectionQuality separately
      // vs when we switch networks in the PpnService. Hence, we gain nothing at the moment by
      // tracking for the other networks.
      if (ppnNetwork.equals(activeNetwork)) {
        ConnectionQuality newConnectionQuality;
        // Unfortunately, getting the Signal Strength from the NetworkCapabilities object is only
        // supported in API version 29+, or VERSION_CODE Q.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          newConnectionQuality =
              this.ppnNetworkSelector.getConnectionQuality(
                  activeNetwork, networkCapabilities.getSignalStrength());
        } else {
          // We do not have the RSSI from NetworkCapabilities. Hence, we will have to rely on
          // getting the RSSI from the appropriate Android Network Manager (Wifi or Telephony)
          newConnectionQuality =
              this.ppnNetworkSelector.getConnectionQuality(activeNetwork, /* rssi= */ 0);
        }
        if (connectionQuality != newConnectionQuality) {
          Log.w(
              TAG,
              "ConnectionQuality Changed! New ConnectionQuality: " + newConnectionQuality.name());
          connectionQuality = newConnectionQuality;
        }
      }
    }
  }

  @Override
  public Task<Boolean> handleNetworkLinkPropertiesChanged(
      PpnNetwork ppnNetwork, LinkProperties linkProperties) {
    Log.w(
        TAG,
        String.format(
            "onLinkPropertiesChanged with network: %s with linkProperties: %s",
            ppnNetwork, linkProperties));

    return ppnNetworkValidator.validateNetwork(ppnNetwork);
  }

  @Override
  public boolean deprioritize(
      com.google.android.libraries.privacy.ppn.internal.NetworkInfo networkInfo) {
    synchronized (lock) {
      long networkId = networkInfo.getNetworkId();
      PpnNetwork ppnNetwork = getPpnNetwork(networkId);

      if (ppnNetwork == null) {
        Log.w(TAG, String.format("No PpnNetwork with id %s to deprioritize", networkId));
        return false;
      }

      if (availableNetworks.size() == 1) {
        Log.w(
            TAG,
            String.format(
                "Cannot deprioritize Network %s -- it is the only available network!", networkId));
        return false;
      }

      Log.w(TAG, String.format("Deprioritizing Network %s", networkId));
      // After deprioritizing we will remove the network validation for that network. The next time
      // we see the NetworkCapabilities or LinkProperties change we will reevaluate it.
      ppnNetworkValidator.clearNetworkValidation(ppnNetwork);
      removeNetwork(ppnNetwork);
      pendingNetworks.add(ppnNetwork);
      return true;
    }
  }

  // Returns the PpnNetwork from available networks corresponding to the passed in Android Network
  // ID, or null if it is not found.
  @Override
  @Nullable
  public PpnNetwork getPpnNetwork(long networkId) {
    synchronized (lock) {
      for (PpnNetwork ppnNetwork : availableNetworks) {
        if (ppnNetwork.getNetworkId() == networkId) {
          return ppnNetwork;
        }
      }

      return null;
    }
  }

  @Override
  public void reevaluateNetworks() {
    synchronized (lock) {
      Log.w(TAG, "Reevaluating Networks");
      evaluateNetworkStrategy();
    }
  }

  @Override
  public JSONObject getDebugJson() {
    synchronized (lock) {
      XenonDebugJson.Builder builder = new XenonDebugJson.Builder();

      for (PpnNetwork network : availableNetworks) {
        builder.addAvailableNetwork(network);
      }
      if (activeNetwork != null) {
        builder.setActiveNetwork(activeNetwork);
      }
      for (PpnNetwork network : pendingNetworks) {
        builder.addPendingNetwork(network);
      }
      builder.setConnectionQuality(connectionQuality);

      return builder.build();
    }
  }

  @Override
  public void validationPassed(PpnNetwork ppnNetwork, AddressFamily addressFamily) {
    synchronized (lock) {
      promoteNetwork(ppnNetwork, addressFamily);
      // We need to blindly call evaluateNetworkStrategy to handle cleaning up disconnected.
      evaluateNetworkStrategy();
      printAvailableNetworkMap();
    }
  }

  private void releaseAllNetworkRequests() {
    if (this.wifiCallback != null) {
      releaseNetworkRequest(this.wifiCallback);
      this.wifiCallback = null;
    }
    if (this.cellularCallback != null) {
      releaseNetworkRequest(this.cellularCallback);
      this.cellularCallback = null;
    }
  }

  // Method that will evaluate with PpnNetworkSelector to get the new best network.
  private void evaluateNetworkStrategy() {
    synchronized (lock) {
      if (isEvaluatingNetworks) {
        Log.w(TAG, "[EvaluateNetworkStrategy] Already evaluating, ignoring this method call.");
        return;
      }
      isEvaluatingNetworks = true;

      try {
        cleanUpNetworkMaps();

        PpnNetwork bestNetwork = ppnNetworkSelector.getBestNetwork(getAllNetworks());
        if (bestNetwork == null) {
          Log.w(TAG, "[EvaluateNetworkStrategy] No bestNetwork available.");
          return;
        }

        // If the new bestNetwork is different from the current active one, update and publish.
        if (!bestNetwork.equals(activeNetwork)) {
          Log.w(
              TAG,
              String.format(
                  "[EvaluateNetworkStrategy] Switching best network from %s to %s.",
                  activeNetwork, bestNetwork));

          activeNetwork = bestNetwork;
          mainHandler.post(() -> listener.onNetworkAvailable(bestNetwork));

          // We need to reset the ConnectionQuality and publish this event whenever we switch to a
          // new network because we rely on differences between the cached value and what is
          // published from Android to publish a change upwards via our listener.
          connectionQuality = ConnectionQuality.UNKNOWN_QUALITY;
          Log.w(TAG, "[EvaluateNetworkStrategy] Network selected: " + activeNetwork);
        } else {
          Log.w(
              TAG,
              String.format(
                  "[EvaluateNetworkStrategy] activeNetwork %s is already bestNetwork %s",
                  activeNetwork, bestNetwork));
        }
      } finally {
        // We need to make sure we ALWAYS reset the evaluating variable.
        isEvaluatingNetworks = false;
      }
    }
  }

  // Goes through the pending and available network maps and checks whether networks are still
  // connected. If not, remove them from their respective maps.
  @VisibleForTesting
  void cleanUpNetworkMaps() {
    synchronized (lock) {
      ConnectivityManager connectivityManager = getConnectivityManager();

      Iterator<PpnNetwork> pendingNetworkIterator = pendingNetworks.iterator();

      // Go through pendingNetworks and remove any networks that Android is no longer aware of.
      while (pendingNetworkIterator.hasNext()) {
        PpnNetwork ppnNetwork = pendingNetworkIterator.next();
        // Check whether the network has a valid NetworkCapabilities or NetworkInfo. If neither
        // exist, then Android is NOT tracking this network and we should remove it.
        if ((connectivityManager.getNetworkCapabilities(ppnNetwork.getNetwork()) == null)
            || (connectivityManager.getNetworkInfo(ppnNetwork.getNetwork()) == null)) {
          Log.w(
              TAG,
              String.format(
                  "[PendingNetworks] PpnNetwork %s is removed from PendingNetworks.", ppnNetwork));
          pendingNetworkIterator.remove();
        } else {
          Log.w(
              TAG,
              String.format(
                  "[PendingNetworks] PpnNetwork %s is healthy in PendingNetworks.", ppnNetwork));
        }
      }

      Iterator<PpnNetwork> availableNetworkIterator = availableNetworks.iterator();
      ArrayList<PpnNetwork> networksToRemove = new ArrayList<>();
      ArrayList<PpnNetwork> networksToPending = new ArrayList<>();

      // Iterate through all the available networks and establish which networks to remove or move
      // to pending.
      while (availableNetworkIterator.hasNext()) {
        PpnNetwork ppnNetwork = availableNetworkIterator.next();
        NetworkInfo networkInfo = getConnectivityManager().getNetworkInfo(ppnNetwork.getNetwork());

        // Check whether the network has a valid NetworkCapabilities or NetworkInfo. If neither
        // exist, then Android is NOT tracking this network and we should remove it.
        if ((connectivityManager.getNetworkCapabilities(ppnNetwork.getNetwork()) == null)
            || (networkInfo == null)) {
          networksToRemove.add(ppnNetwork);
        } else if (!networkInfo.isConnected()) {
          networksToPending.add(ppnNetwork);
        } else {
          Log.w(
              TAG,
              String.format(
                  "[AvailableNetworks] PpnNetwork %s is connected and healthy.", ppnNetwork));
        }
      }

      for (PpnNetwork ppnNetwork : networksToPending) {
        Log.w(
            TAG,
            String.format(
                "[AvailableNetworks] PpnNetwork %s is NOT connected so moving to PendingNetworks"
                    + " from AvailableMap.",
                ppnNetwork));
        pendingNetworks.add(ppnNetwork);
        removeNetwork(ppnNetwork);
      }

      for (PpnNetwork ppnNetwork : networksToRemove) {
        Log.w(
            TAG,
            String.format(
                "[AvailableNetworks] PpnNetwork %s has null Network so is removed from"
                    + " AvailableMap.",
                ppnNetwork));
        removeNetwork(ppnNetwork);
      }
    }
  }

  private void requestNetwork(PpnNetworkCallback ppnNetworkCallback) {
    Log.w(TAG, String.format("Request Network for %s", ppnNetworkCallback));
    ConnectivityManager connectivityManager = getConnectivityManager();
    try {
      connectivityManager.requestNetwork(
          ppnNetworkCallback.getNetworkRequest(), ppnNetworkCallback);
    } catch (RuntimeException e) {
      Log.e(TAG, String.format("Failed to request Network for %s", ppnNetworkCallback), e);
    }
  }

  /** Release the {@link NetworkRequest} for the given {@link NetworkCallback} */
  private void releaseNetworkRequest(PpnNetworkCallback ppnNetworkCallback) {
    Log.w(TAG, String.format("Releasing Network Callback Request for %s", ppnNetworkCallback));
    ConnectivityManager connectivityManager = getConnectivityManager();
    try {
      connectivityManager.unregisterNetworkCallback(ppnNetworkCallback);
      ppnNetworkCallback = null;
    } catch (IllegalArgumentException e) {
      Log.e(TAG, String.format("Failed to release request for %s", ppnNetworkCallback), e);
    }
  }

  /**
   * Adds a network to the available network set and removes it from the pending set, if it is still
   * listed as pending. If it is not in the pending list, it will be ignored.
   */
  private void promoteNetwork(PpnNetwork ppnNetwork, AddressFamily addressFamily) {
    synchronized (lock) {
      if (pendingNetworks.remove(ppnNetwork)) {
        ppnNetwork.setConnectivity(addressFamily);
        addNetwork(ppnNetwork);
      }
    }
  }

  private void addNetwork(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      availableNetworks.add(ppnNetwork);
      evaluateNetworkStrategy();
    }
  }

  private void removeNetwork(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      if (ppnNetwork.equals(activeNetwork)) {
        clearActiveNetwork();
      }

      availableNetworks.remove(ppnNetwork);

      if (availableNetworks.isEmpty()) {
        // Clear the ActiveNetwork just in case as we want to be in a clean state whenever we have
        // no available networks.
        clearActiveNetwork();

        mainHandler.post(() -> listener.onNetworkUnavailable(NetworkUnavailableReason.UNKNOWN));
      } else if (activeNetwork == null) {
        // We only need to evaluate the NetworkStrategy again if there are availableNetworks and
        // we did NOT remove the current active network.
        evaluateNetworkStrategy();
      }
    }
  }

  // Handles all the necessary clean up of the ActiveNetwork.
  private void clearActiveNetwork() {
    Log.w(TAG, "Clearing active network.");
    activeNetwork = null;
    connectionQuality = ConnectionQuality.UNKNOWN_QUALITY;
  }

  // Clears all state stored in this PpnNetworkManager.
  private void clearState() {
    clearActiveNetwork();
    availableNetworks.clear();
    mainHandler.post(() -> listener.onNetworkUnavailable(NetworkUnavailableReason.UNKNOWN));
  }

  private boolean containsPpnNetwork(PpnNetwork ppnNetwork) {
    return availableNetworks.contains(ppnNetwork);
  }

  private ConnectivityManager getConnectivityManager() {
    return (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
  }

  // Setting the ConnectionQuality requires a lot of overhead work in the unit tests that includes
  // mocking across 2 classes, 2 Android system services, and mocking NetworkCapability fields.
  // Exposing such a method greatly simplifies and improves the readability of the unit test.
  @VisibleForTesting
  void setConnectionQuality(ConnectionQuality connectionQuality) {
    synchronized (lock) {
      this.connectionQuality = connectionQuality;
    }
  }

  @VisibleForTesting
  ConnectionQuality getConnectionQuality() {
    synchronized (lock) {
      return connectionQuality;
    }
  }

  @VisibleForTesting
  PpnNetwork getActiveNetwork() {
    synchronized (lock) {
      return activeNetwork;
    }
  }

  @VisibleForTesting
  ImmutableList<PpnNetwork> getPendingNetworks() {
    synchronized (lock) {
      return ImmutableList.copyOf(pendingNetworks);
    }
  }

  // Temporary print method to aid in further understanding of Xenon as we use it for a while.
  private void printAvailableNetworkMap() {
    // Printing active networks.
    String availableNetworksString = "[";
    for (PpnNetwork network : this.getAllNetworks()) {
      availableNetworksString += network;
      availableNetworksString += ",";
    }
    availableNetworksString =
        availableNetworksString.substring(0, availableNetworksString.length() - 1);
    availableNetworksString += "]";
    Log.w(TAG, "[AvailableNetworksMap]" + availableNetworksString);

    // Print Pending networks.
    String pendingNetworksString = "[";
    for (PpnNetwork network : this.getPendingNetworks()) {
      pendingNetworksString += network;
      pendingNetworksString += ",";
    }
    pendingNetworksString = pendingNetworksString.substring(0, pendingNetworksString.length() - 1);
    pendingNetworksString += "]";
    Log.w(TAG, "[PendingNetworksMap]" + pendingNetworksString);
  }
}
