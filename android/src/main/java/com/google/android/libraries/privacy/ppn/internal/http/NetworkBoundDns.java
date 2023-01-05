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

package com.google.android.libraries.privacy.ppn.internal.http;

import android.net.Network;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** A Dns implementation that uses a specific network. */
public class NetworkBoundDns implements Dns {
  private static final String TAG = "NetworkBoundDns";

  private final Network network;
  private final AddressFamily addressFamily;

  NetworkBoundDns(PpnNetwork ppnNetwork, AddressFamily addressFamily) {
    this.network = ppnNetwork.getNetwork();
    this.addressFamily = addressFamily;
  }

  @Override
  public List<InetAddress> lookup(String host) throws UnknownHostException {
    Log.w(TAG, "Doing DNS lookup on network " + network + " for host: " + host);

    List<InetAddress> addresses = Arrays.asList(network.getAllByName(host));

    if (addressFamily == AddressFamily.V4V6) {
      return addresses;
    }

    List<InetAddress> matchingAddresses = new ArrayList<>();
    for (InetAddress address : addresses) {
      if ((addressFamily == AddressFamily.V4 && address instanceof Inet4Address)
          || (addressFamily == AddressFamily.V6 && address instanceof Inet6Address)) {
        matchingAddresses.add(address);
      }
    }

    return matchingAddresses;
  }
}
