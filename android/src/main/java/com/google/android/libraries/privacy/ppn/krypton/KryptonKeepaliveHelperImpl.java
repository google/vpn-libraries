// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

package com.google.android.libraries.privacy.ppn.krypton;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import android.net.SocketKeepalive;
import android.util.Log;
import androidx.annotation.Nullable;
import java.net.InetAddress;

/** Implementation of KryptonKeepaliveHelper */
public final class KryptonKeepaliveHelperImpl implements KryptonKeepaliveHelper {
  private static final String TAG = "KryptonKeepaliveImpl";

  private final Context context;

  @Nullable private SocketKeepalive keepalive = null;
  @Nullable private Runnable startNewKeepalive = null;

  private boolean keepaliveStarted = false;

  // A lock guarding all of the mutable state of this class.
  private final Object lock = new Object();

  public KryptonKeepaliveHelperImpl(Context context) {
    this.context = context;
  }

  @Override
  public void startKeepalive(
      Network network,
      UdpEncapsulationSocket socket,
      InetAddress localAddress,
      InetAddress destinationAddress,
      int keepaliveIntervalSeconds,
      @Nullable Runnable startCallback) {
    synchronized (lock) {
      if (keepalive != null) {
        keepalive.close();
        keepalive = null;
      }

      keepalive =
          ((ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE))
              .createSocketKeepalive(
                  network,
                  socket,
                  localAddress,
                  destinationAddress,
                  context.getMainExecutor(),
                  new SocketKeepalive.Callback() {
                    @Override
                    public void onDataReceived() {
                      Log.e(TAG, "Keepalive socket received data and will be killed.");
                    }

                    @Override
                    public void onError(int error) {
                      Log.e(TAG, "Keepalive socket encountered an error and will stop: " + error);
                    }

                    @Override
                    public void onStarted() {
                      synchronized (lock) {
                        Log.i(TAG, "Keepalive socket has been started.");
                        if (startCallback != null) {
                          startCallback.run();
                        }
                        keepaliveStarted = true;
                      }
                    }

                    @Override
                    public void onStopped() {
                      synchronized (lock) {
                        Log.i(TAG, "Keepalive socket has been stopped.");
                        keepaliveStarted = false;
                        if (startNewKeepalive != null) {
                          startNewKeepalive.run();
                          startNewKeepalive = null;
                        }
                      }
                    }
                  });

      // If there is a previous keepalive already then start will be called when the previous stops
      if (keepaliveStarted) {
        startNewKeepalive = () -> keepalive.start(keepaliveIntervalSeconds);
      } else {
        keepalive.start(keepaliveIntervalSeconds);
      }
    }
  }

  @Override
  public void stopKeepalive() {
    synchronized (lock) {
      if (keepalive != null) {
        keepalive.close();
        keepalive = null;
      }
      startNewKeepalive = null;
    }
  }
}
