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

package com.google.android.libraries.privacy.ppn.xenon.impl;

import static java.util.stream.Collectors.toList;

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
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus.ConnectionQuality;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.krypton.HttpFetcher;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkCallback;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener.NetworkUnavailableReason;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkManager;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkSelector;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.json.JSONObject;

/**
 * PpnNetworkManagerImpl is the impl of the core service responsible for keeping track of the
 * available networks. It includes the core logic for handling when a network is available, lost,
 * and changed.
 *
 * <p>TODO: Add checks to ensure running on main thread. Or background thread once we
 * switch over implementation to use it.
 *
 * <p>TODO: Re-structure this class so that blocks of `sync` code are better structured
 * and more readable, without use needing to blanket `sync` block everything.
 */
final class PpnNetworkManagerImpl implements PpnNetworkManager {
  private static final String TAG = "PpnNetworkManagerImpl";

  private final Context context;
  private final HashSet<PpnNetwork> availableNetworks;
  private final PpnOptions ppnOptions;

  private final HttpFetcher httpFetcher;
  // Mutex that guards the networks and the callbacks.
  private final Object lock = new Object();

  // Variable that ensures that we only evaluate networks once at a time.
  private boolean isEvaluatingNetworks = false;

  @Nullable private PpnNetworkCallback wifiCallback;
  @Nullable private PpnNetworkCallback cellularCallback;

  private final Handler mainHandler = new Handler(Looper.getMainLooper());
  private final PpnNetworkListener listener;
  private final PpnNetworkSelector ppnNetworkSelector;

  // Set to keep track of the pending available networks to add to our avaiable list.
  // This is currently used specifically for Cellular networks: After a cellular network becomes
  // available, we can only add it to our availableNetwork list when it has successfully established
  // a link address.
  private final HashSet<PpnNetwork> pendingNetworks;

  // Current active Network used. Generally, this is the "best" considered Network.
  @Nullable private PpnNetwork activeNetwork;
  // The current known ConnectionQuality associated with the active network.
  private ConnectionQuality connectionQuality = ConnectionQuality.UNKNOWN_QUALITY;

  // TODO: consider moving into a factory or make this configurable.
  public static final NetworkRequest WIFI_NETWORK_REQUEST =
      new NetworkRequest.Builder()
          // Must have Internet access
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          // And not be another VPN
          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          // And only be on the Wifi interface
          .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
          .build();

  // TODO: consider moving into a factory or make this configurable.
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
    this.ppnOptions = ppnOptions;
    this.availableNetworks = new HashSet<>();
    this.pendingNetworks = new HashSet<>();
    this.ppnNetworkSelector = new PpnNetworkSelectorImpl(context);
    this.httpFetcher = httpFetcher;
  }

  @Override
  public List<PpnNetwork> getAllNetworks() {
    synchronized (lock) {
      return availableNetworks.stream().collect(toList());
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
      pendingNetworks.clear();
      releaseAllNetworkRequests();
      clearState();
    }
  }

  // TODO: Consider moving this logic to the Callbacks.
  @Override
  public void handleNetworkAvailable(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      Log.w(TAG, String.format("Network Available with network: %s", ppnNetwork));

      // TODO: Do we need to handle case where there already exists a network with the
      // same NetworkType?

      // We do not need to verify that the network has been lost. We're guaranteed a callback to
      // onCapabilitiesChanged.

      // For cellular networks, we cannot consider it as an available network until it has
      // established
      // an IP Address.
      if (ppnNetwork.getNetworkType() == NetworkType.CELLULAR) {
        pendingNetworks.add(ppnNetwork);
      } else {
        if (canConnectToInternet(ppnNetwork)) {
          Log.w(TAG, "Connectivity check passed for " + ppnNetwork);
          addNetwork(ppnNetwork);
        } else {
          Log.w(TAG, "Connectivity check failed for " + ppnNetwork);
          pendingNetworks.add(ppnNetwork);
          postConnectivityRecheck(ppnNetwork, ppnOptions.getConnectivityCheckMaxRetries());
        }
      }

      this.printAvailableNetworkMap();
    }
  }

  /** Schedules a retry of a network that has failed a connectivity check. */
  private void postConnectivityRecheck(PpnNetwork network, int retries) {
    if (retries <= 0) {
      Log.w(TAG, "Giving up connectivity check retries for " + network);
      return;
    }

    Log.w(
        TAG,
        "Retrying connectivity check for "
            + network
            + " in "
            + ppnOptions.getConnectivityCheckRetryDelay());
    mainHandler.postDelayed(
        () -> {
          Log.w(TAG, "Posting connectivity check for " + network + " now");
          ppnOptions
              .getBackgroundExecutor()
              .execute(
                  () -> {
                    Log.w(TAG, "Retrying connectivity check for " + network + " now");
                    if (!checkAndHandlePendingNetwork(network)) {
                      synchronized (lock) {
                        if (!pendingNetworks.contains(network)) {
                          Log.w(
                              TAG,
                              "Not retrying connectivity check for removed network: " + network);
                          return;
                        }
                      }
                      postConnectivityRecheck(network, retries - 1);
                    }
                  });
        },
        ppnOptions.getConnectivityCheckRetryDelay().toMillis());
  }

  @Override
  public void handleNetworkLost(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      Log.w(TAG, String.format("Network Lost with network: %s", ppnNetwork));

      // If lost network is not tracked, ignore.
      if (!containsPpnNetwork(ppnNetwork)) {
        return;
      }
      removeNetwork(ppnNetwork);

      this.printAvailableNetworkMap();
    }
  }

  @Override
  public void handleNetworkCapabilitiesChanged(
      PpnNetwork ppnNetwork, NetworkCapabilities networkCapabilities) {
    synchronized (lock) {
      Log.w(
          TAG,
          String.format(
              "onCapabilitiesChanged for network: %s with networkCapabilities: %s",
              ppnNetwork, networkCapabilities));

      checkAndHandlePendingNetwork(ppnNetwork);

      this.printAvailableNetworkMap();

      if (networkCapabilities == null) {
        // Network was lost. No action here as it should be handled by onLost NetworkCallback.
        return;
      }
      // If network is not tracked, ignore.
      if (!containsPpnNetwork(ppnNetwork)) {
        Log.w(
            TAG,
            String.format(
                "onCapabilitiesChanged. Network NOT in our Map. Network: %s", ppnNetwork));
        return;
      }

      // Validate the current Network. If it fails away of these conditions, remove the network.
      // TODO: Switching networks on device, new Network is not VALIDATED. Investigate.
      if (!networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          || !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)) {
        Log.w(
            TAG,
            String.format("onCapabilitiesChanged. Removing Network as Capability is not valid"));
        removeNetwork(ppnNetwork);
        return;
      }

      // If the current activeNetwork has a different ConnectionQuality, we need to update and
      // publish
      // this change to the listener. We currently only support tracking the ConnectionQuality of
      // the
      // activeNetwork because we handle the ConnectionQuality separately vs when we switch networks
      // in the PpnService. Hence, we gain nothing at the moment by tracking for the other networks.
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
          // getting
          // the RSSI from the appropriate Android Network Manager (Wifi or Telephony)
          newConnectionQuality =
              this.ppnNetworkSelector.getConnectionQuality(
                  activeNetwork,
                  /** rssi= */
                  0);
        }
        if (connectionQuality != newConnectionQuality) {
          Log.w(
              TAG,
              "ConnectionQuality Changed! New ConnectionQuality: " + newConnectionQuality.name());
          connectionQuality = newConnectionQuality;
          mainHandler.post(
              () ->
                  listener.onNetworkStatusChanged(
                      ppnNetwork,
                      createConnectionStatus(ppnNetwork.getNetworkType(), connectionQuality)));
        }
      }

      // We need to bindly call evaluateNetworkStrategy to handle cleaning up disconnected.
      // TODO: Revisit this.
      evaluateNetworkStrategy();

      // TODO: Check Network Strength and make changes depending on it.
    }
  }

  @Override
  public void handleNetworkLinkPropertiesChanged(
      PpnNetwork ppnNetwork, LinkProperties linkProperties) {
    synchronized (lock) {
      Log.w(
          TAG,
          String.format(
              "onLinkPropertiesChanged with network: %s with linkProperties: %s",
              ppnNetwork, linkProperties));

      checkAndHandlePendingNetwork(ppnNetwork);

      // We need to bindly call evaluateNetworkStrategy to handle cleaning up disconnected.
      // TODO: Revisit this.
      evaluateNetworkStrategy();

      this.printAvailableNetworkMap();

      // TODO: Address MTU in follow-up.
    }
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
      builder.setConnectionQuality(connectionQuality);

      return builder.build();
    }
  }

  // Checks if the provided PpnNetwork is a Pending Network. If it is, verify if the network can
  // bind to a socket. If so, remove it from pending and add it to our available network map.
  private boolean checkAndHandlePendingNetwork(PpnNetwork ppnNetwork) {
    synchronized (lock) {
      if (!pendingNetworks.contains(ppnNetwork)) {
        return false;
      }
      Log.w(TAG, String.format("Evaluating Pending Network: %s", ppnNetwork));

      // If this PpnNetwork can successfully connect to the internet. There are cases where this
      // does not work due to multiple Cellular networks and dual SIMs, or the Wifi network has a
      // captive portal.
      if (canConnectToInternet(ppnNetwork)) {
        Log.w(
            TAG,
            String.format(
                "Pending Network %s PASSES Connectivity check. Moving from Pending to Available"
                    + " Map.",
                ppnNetwork));
        pendingNetworks.remove(ppnNetwork);
        addNetwork(ppnNetwork);
        return true;
      } else {
        Log.w(TAG, String.format("Pending Network %s FAILED connectivity check.", ppnNetwork));
      }
    }
    return false;
  }

  // Checks whether the PpnNetwork has internet checking whether we can bind a socket to this
  // PpnNetwork and in the case of Wifi, whether we can establish a quick Url connection.
  private boolean canConnectToInternet(PpnNetwork ppnNetwork) {
    DatagramSocket socket;
    try {
      socket = new DatagramSocket();
    } catch (SocketException e) {
      Log.w(
          TAG,
          String.format(
              "Unable to create socket to check whether PpnNetwork %s has Internet.", ppnNetwork),
          e);
      return false;
    }

    try {
      ppnNetwork.getNetwork().bindSocket(socket);
    } catch (IOException e) {
      Log.w(
          TAG,
          String.format(
              "Unable to bind socket to check whether PpnNetwork %s has Internet.", ppnNetwork),
          e);
      return false;
    } finally {
      socket.close();
    }

    if (ppnNetwork.getNetworkType() == NetworkType.WIFI) {
      Log.w(TAG, String.format("Checking WiFi Connectivity for network %s", ppnNetwork));
      boolean pingSuccessful =
          httpFetcher.checkGet(
              ppnOptions.getConnectivityCheckUrl(),
              /** headers= */
              null,
              ppnNetwork);
      if (!pingSuccessful) {
        Log.w(TAG, String.format("PpnNetwork %s FAILS WiFi Connectivity check.", ppnNetwork));
        return false;
      }
      Log.w(TAG, String.format("PpnNetwork %s PASSES WiFi Connectivity check.", ppnNetwork));
    }

    Log.w(TAG, String.format("PpnNetwork %s CAN connect to Internet.", ppnNetwork));
    return true;
  }

  private static ConnectionStatus createConnectionStatus(
      NetworkType networkType, ConnectionQuality connectionQuality) {
    return ConnectionStatus.newBuilder()
        .setNetworkType(networkType)
        .setQuality(connectionQuality)
        .build();
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
        // We need to take a pass and clean up our Network maps as we potentially can have
        // non-connected networks.
        // TODO: Revisit this.
        cleanUpNetworkMaps();

        PpnNetwork bestNetwork = ppnNetworkSelector.getBestNetwork(getAllNetworks());
        if (bestNetwork == null) {
          Log.w(TAG, "[EvaluateNetworkStrategy] No bestNetwork available.");
          return;
        }

        // If the new bestNetwork is different from the current active one, update and publish.
        if (!bestNetwork.equals(activeNetwork)) {
          activeNetwork = bestNetwork;

          Log.w(
              TAG,
              String.format(
                  "[EvaluateNetworkStrategy] Network Switch! New Best Network: %s.",
                  activeNetwork));
          mainHandler.post(() -> listener.onNetworkAvailable(bestNetwork));

          // We need to reset the ConnectionQuality and publish this event whenever we switch to a
          // new network because we rely on differences between the cached value and what is
          // published from Android to publish a change upwards via our listener.
          connectionQuality = ConnectionQuality.UNKNOWN_QUALITY;
          Log.w(TAG, "[EvaluateNetworkStrategy] Network selected: " + activeNetwork);
          mainHandler.post(
              () ->
                  listener.onNetworkStatusChanged(
                      bestNetwork,
                      createConnectionStatus(bestNetwork.getNetworkType(), connectionQuality)));
        } else {
          Log.w(
              TAG,
              String.format(
                  "[EvaluateNetworkStrategy] activeNetwork %s is already bestNetwork",
                  activeNetwork));
        }
      } finally {
        // We need to make sure we ALWAYS reset the evaluting variable.
        isEvaluatingNetworks = false;
      }
    }
  }

  // Goes through the pending and available network maps and checks whether networks are still
  // connected. If not, remove them from their respective maps.
  // TODO: Figure out why we are not getting onLost callbacks for cell network lost.
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

  private void addNetwork(PpnNetwork ppnNetwork) {
    availableNetworks.add(ppnNetwork);
    evaluateNetworkStrategy();
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

        // TODO: Get data on whether Network is unavailable due to Airplane mode.
        mainHandler.post(() -> listener.onNetworkUnavailable(NetworkUnavailableReason.UNKNOWN));

        // When there are no availableNetworks, we need to update the connection quality for the
        // last known Network to be NO_SIGNAL.
        mainHandler.post(
            () ->
                listener.onNetworkStatusChanged(
                    ppnNetwork,
                    createConnectionStatus(NetworkType.UNKNOWN_TYPE, ConnectionQuality.NO_SIGNAL)));
      } else if (activeNetwork == null) {
        // We only need to evaluate the NetworkStrategy again if there are availableNetworks and
        // we did NOT remove the current active network.
        evaluateNetworkStrategy();
      }
    }
  }

  // Handles all the necessary clean up of the ActiveNetwork.
  private void clearActiveNetwork() {
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
  List<PpnNetwork> getPendingNetworks() {
    synchronized (lock) {
      return pendingNetworks.stream().collect(toList());
    }
  }

  // Temporary print method to aid in further understanding of Xenon as we use it for a while.
  // TODO: Remove later once we have better understanding of various edge cases.
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
