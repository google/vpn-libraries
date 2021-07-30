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
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/** A Dns implementation that uses a specific network. */
public class NetworkBoundDns implements Dns {
  private static final String TAG = "NetworkBoundDns";

  private final Network network;

  NetworkBoundDns(PpnNetwork ppnNetwork) {
    this.network = ppnNetwork.getNetwork();
  }

  @Override
  public List<InetAddress> lookup(String host) throws UnknownHostException {
    Log.w(TAG, "Doing DNS lookup on network " + network + " for host: " + host);
    return Arrays.asList(network.getAllByName(host));
  }
}
