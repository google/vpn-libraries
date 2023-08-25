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

package com.google.android.libraries.privacy.ppn.neon;

import android.net.Network;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;

/** Creates sockets that bypasses PPN, if it's running, for VPN management APIs. */
public class ProvisionSocketFactory extends SocketFactory {
  private static final String TAG = "ProvisionSocketFactory";
  @Nullable private final Network network;

  ProvisionSocketFactory(@Nullable Network network) {
    this.network = network;
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    return bindSocket(getDefault().createSocket(host, port));
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException {
    return bindSocket(getDefault().createSocket(host, port, localHost, localPort));
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return bindSocket(getDefault().createSocket(host, port));
  }

  @Override
  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
      throws IOException {
    return bindSocket(getDefault().createSocket(address, port, localAddress, localPort));
  }

  @Override
  public Socket createSocket() throws IOException {
    return bindSocket(getDefault().createSocket());
  }

  /** Convenience method to bind the socket to the current network. */
  @CanIgnoreReturnValue
  private Socket bindSocket(Socket socket) {
    if (network != null) {
      try {
        network.bindSocket(socket);
      } catch (IOException e) {
        Log.e(TAG, "Unable to bind socket to network: " + network, e);
      }
    } else {
      Log.w(TAG, "A socket was created but not bound to a network.");
    }
    return socket;
  }
}
