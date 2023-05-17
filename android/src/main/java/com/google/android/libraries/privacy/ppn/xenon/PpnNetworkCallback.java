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

import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;

/**
 * PpnNetworkCallback is PPN's version of the Android NetworkCallback. It is the object that stores
 * all relevant information associated with a Network session: mostly including additional PPN
 * Network specific information.
 */
public final class PpnNetworkCallback extends NetworkCallback {
  private final PpnNetworkManager networkManager;
  private final NetworkType networkType;
  // The corresponding NetworkRequest associated with this NetworkCallback.
  private final NetworkRequest networkRequest;

  // TAG used for Logging
  private static final String TAG = "PpnNetworkCallback";

  public PpnNetworkCallback(
      PpnNetworkManager networkManager, NetworkType networkType, NetworkRequest networkRequest) {
    this.networkManager = networkManager;
    this.networkType = networkType;
    this.networkRequest = networkRequest;
  }

  public NetworkRequest getNetworkRequest() {
    return networkRequest;
  }

  public NetworkType getNetworkType() {
    return networkType;
  }

  @Override
  public void onAvailable(Network network) {
    Log.w(TAG, String.format("%s Network callback: onAvailable", this));
    PpnNetwork ppnNetwork = new PpnNetwork(network, this.networkType);
    networkManager.handleNetworkAvailable(ppnNetwork);
  }

  @Override
  public void onLost(Network network) {
    Log.w(TAG, String.format("%s Network callback: onLost", this));
    PpnNetwork ppnNetwork = new PpnNetwork(network, this.networkType);
    networkManager.handleNetworkLost(ppnNetwork);
  }

  @Override
  public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
    Log.w(TAG, String.format("%s Network callback: onCapabilitiesChanged", this));
    PpnNetwork ppnNetwork = new PpnNetwork(network, this.networkType);
    networkManager.handleNetworkCapabilitiesChanged(ppnNetwork, networkCapabilities);
  }

  @Override
  public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
    Log.w(TAG, String.format("%s Network callback: onLinkPropertiesChanged", this));
    PpnNetwork ppnNetwork = new PpnNetwork(network, this.networkType);
    networkManager.handleNetworkLinkPropertiesChanged(ppnNetwork, linkProperties);
  }

  @Override
  public void onBlockedStatusChanged(Network network, boolean blocked) {
    Log.w(TAG, String.format("%s Network callback: onBlockedStatusChanged (%b)", this, blocked));
  }

  @Override
  public String toString() {
    return String.format("PpnNetworkCallback<%s>", this.networkType.name());
  }
}
