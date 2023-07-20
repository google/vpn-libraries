// Copyright 2023 Google LLC
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

import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;
import java.util.HashMap;

/** Tracks when VPN networks on the device are created, updated, or destroyed. */
final class VpnMonitor extends NetworkCallback {
  private static final String TAG = "VpnMonitor";

  private static final NetworkRequest VPN_NETWORK_REQUEST =
      new NetworkRequest.Builder()
          .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
          .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          .build();

  private final ConnectivityManager connectivityManager;

  private final HashMap<Network, VpnLinkProperties> linkPropertiesMap = new HashMap<>();

  private boolean running = false;

  public VpnMonitor(ConnectivityManager connectivityManager) {
    this.connectivityManager = connectivityManager;
  }

  public void start() {
    Log.w(TAG, "Starting VPN Monitor");
    synchronized (this) {
      if (running) {
        Log.w(TAG, "VPN Monitor is already running");
        return;
      }
      requestNetwork();
      running = true;
    }
  }

  public void stop() {
    Log.w(TAG, "Stopping VPN Monitor");
    synchronized (this) {
      releaseNetworkRequest();
      running = false;
    }
    linkPropertiesMap.clear();
  }

  @Override
  public void onAvailable(Network network) {
    Log.w(TAG, String.format("VPN Network Available (%s)", network));
  }

  @Override
  public void onLost(Network network) {
    Log.w(TAG, String.format("VPN Network Lost (%s)", network));
    linkPropertiesMap.remove(network);
  }

  @Override
  public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
    Log.w(
        TAG,
        String.format(
            "VPN Network capabilities changed for Network %s: %s", network, networkCapabilities));
  }

  @Override
  public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
    VpnLinkProperties newVpnLinkProperties = VpnLinkProperties.fromLinkProperties(linkProperties);
    VpnLinkProperties oldVpnLinkProperties = linkPropertiesMap.put(network, newVpnLinkProperties);
    if (newVpnLinkProperties.equals(oldVpnLinkProperties)) {
      return;
    }

    Log.w(
        TAG,
        String.format(
            "VPN Link Properties changed for Network %s: %s", network, newVpnLinkProperties));
  }

  /** Starts requesting callbacks for VPN networks from the ConnectivityManager. */
  private void requestNetwork() {
    Log.w(TAG, "Requesting network callbacks for VPN networks");
    try {
      this.connectivityManager.registerNetworkCallback(VPN_NETWORK_REQUEST, this);
    } catch (RuntimeException e) {
      Log.e(TAG, "Failed to request network callbacks for VPN networks", e);
    }
  }

  /** Unregisters callbacks for VPN networks with the ConnectivityManager. */
  private void releaseNetworkRequest() {
    Log.w(TAG, "Releasing network callback request for VPN networks");
    try {
      this.connectivityManager.unregisterNetworkCallback(this);
    } catch (IllegalArgumentException e) {
      Log.e(TAG, "Failed to release request for VPN networks", e);
    }
  }
}
