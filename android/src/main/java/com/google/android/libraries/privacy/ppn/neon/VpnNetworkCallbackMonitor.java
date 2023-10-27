/*
 * Copyright (C) 2023 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.libraries.privacy.ppn.neon;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;

/** Vpn NetworkCallback implementation. */
@TargetApi(33)
public final class VpnNetworkCallbackMonitor {
  private static final String TAG = "VpnNetworkCallback";

  private static final NetworkCallback NETWORK_CALLBACK =
      new ConnectivityManager.NetworkCallback() {
        @Override
        public void onAvailable(Network network) {
          Log.v(TAG, "onAvailable(), network: " + network);
        }

        @Override
        public void onLost(Network network) {
          Log.v(TAG, "onLost(), network: " + network);
        }

        @Override
        public void onLosing(Network network, int maxMsToLive) {
          Log.v(TAG, "onLosing(), network: " + network + ", maxMsToLive: " + maxMsToLive);
        }

        @Override
        public void onUnavailable() {
          Log.v(TAG, "onUnavailable()");
        }

        @Override
        public void onCapabilitiesChanged(
            Network network, NetworkCapabilities networkCapabilities) {
          Log.v(
              TAG,
              "onCapabilitiesChanged(), network: "
                  + network
                  + ", networkCapabilities: "
                  + networkCapabilities);
          if (isVpnNetwork(networkCapabilities)) {
            if (isVpnConnected(networkCapabilities)) {
              IkePpnStateTracker.getInstance().setConnected();
            } else {
              IkePpnStateTracker.getInstance().setDisconnected();
            }
          }
        }

        @Override
        public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
          Log.v(
              TAG,
              "onLinkPropertiesChanged(), network: "
                  + network
                  + ", linkProperties: "
                  + linkProperties);
        }

        @Override
        public void onBlockedStatusChanged(Network network, boolean blocked) {
          Log.v(TAG, "onBlockedStatusChanged(), network: " + network + ", blocked: " + blocked);
        }

        private boolean isVpnNetwork(NetworkCapabilities networkCapabilities) {
          return networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        }

        private boolean isVpnConnected(NetworkCapabilities networkCapabilities) {
          return (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                  || networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                  || networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
              && networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
              && networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
        }
      };

  public void registerNetworkCallback(Context context) {
    Log.v(TAG, "registerNetworkCallback()");

    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

    NetworkRequest networkRequest =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            .build();
    connectivityManager.registerNetworkCallback(networkRequest, NETWORK_CALLBACK);
  }

  public void unregisterNetworkCallback(Context context) {
    Log.v(TAG, "unregisterNetworkCallback()");
    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    connectivityManager.unregisterNetworkCallback(NETWORK_CALLBACK);
  }
}
