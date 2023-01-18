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

import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.Network;
import androidx.annotation.Nullable;
import java.net.InetAddress;

/** Helper class for setting up keepalives in Android Krypton library. */
public interface KryptonKeepaliveHelper {
  /**
   * Attempts to start sending keepalive packets with the provided configuration. If there was a
   * keepalive already sending it will be stopped before this is started.
   */
  void startKeepalive(
      Network network,
      UdpEncapsulationSocket socket,
      InetAddress localAddress,
      InetAddress destinationAddress,
      int keepaliveIntervalSeconds,
      @Nullable Runnable startCallback);

  /** Stops the sending of keepalive packets. */
  void stopKeepalive();
}
