// Copyright 2021 Google LLC
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

package com.google.android.libraries.privacy.ppn.internal.service;

import android.net.Network;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.Dns;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * A Dns implementation that uses the underlying network for the VPN, to be used for http
 * connections that are used to reconnect the VPN when it's not connected.
 */
public class VpnBypassDns implements Dns {
  private static final String TAG = "VpnBypassDns";

  private final VpnManager vpnManager;
  private final Dns fallbackDns;

  public VpnBypassDns(VpnManager vpnManager) {
    this.vpnManager = vpnManager;
    this.fallbackDns = HttpFetcher.DEFAULT_DNS;
  }

  VpnBypassDns(VpnManager vpnManager, Dns fallbackDns) {
    this.vpnManager = vpnManager;
    this.fallbackDns = fallbackDns;
  }

  @Override
  public List<InetAddress> lookup(String host) throws UnknownHostException {
    Network network = vpnManager.getNetwork();
    if (network == null) {
      Log.w(TAG, "Doing DNS lookup on default interface for host: " + host);
      return fallbackDns.lookup(host);
    }

    Log.w(TAG, "Doing DNS lookup on network " + network + " for host: " + host);
    return Arrays.asList(network.getAllByName(host));
  }
}
