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

package com.google.android.libraries.privacy.ppn.internal.service;

import android.net.Network;
import android.util.Log;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.function.Supplier;
import javax.net.SocketFactory;

/** Creates sockets that bypasses PPN, if it's running, for VPN management APIs. */
public class ProtectedSocketFactory extends SocketFactory {
  private static final String TAG = "ProtectedSocketFactory";
  private final VpnManager vpnManager;
  private final Supplier<Network> networkProvider;

  ProtectedSocketFactory(VpnManager vpnManager, Supplier<Network> networkProvider) {
    this.vpnManager = vpnManager;
    this.networkProvider = networkProvider;
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    return protect(getDefault().createSocket(host, port));
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException {
    return protect(getDefault().createSocket(host, port, localHost, localPort));
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return protect(getDefault().createSocket(host, port));
  }

  @Override
  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
      throws IOException {
    return protect(getDefault().createSocket(address, port, localAddress, localPort));
  }

  @Override
  public Socket createSocket() throws IOException {
    return protect(getDefault().createSocket());
  }

  /**
   * Convenience method to protect a socket (if the VPN is running), bind the socket (if a network
   * has been set), and return it.
   */
  @CanIgnoreReturnValue
  private Socket protect(Socket socket) {
    vpnManager.protect(socket);

    Network network = networkProvider.get();
    if (network != null) {
      try {
        network.bindSocket(socket);
      } catch (IOException e) {
        Log.e(TAG, "Unable to bind socket to network: " + network, e);
      }
    } else {
      Log.w(TAG, "A socket was created for PPN before the network was set.");
    }

    return socket;
  }
}
