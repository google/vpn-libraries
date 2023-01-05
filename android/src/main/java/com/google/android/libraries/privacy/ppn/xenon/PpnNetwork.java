// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.xenon;

import android.net.Network;
import android.os.Build;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import java.util.concurrent.atomic.AtomicLong;
import org.joda.time.DateTime;

/** PpnNetwork used for a PpnConnection. */
public final class PpnNetwork {
  // Used to generate a network ID on older versions of Android.
  private static final AtomicLong nextNetworkId = new AtomicLong(0);

  private final NetworkType networkType;
  private final Network network;
  private final DateTime creationTime;
  private final long networkId;
  private AddressFamily connectivity;

  public PpnNetwork(Network network, NetworkType networkType) {
    this.network = network;
    this.networkType = networkType;
    this.creationTime = DateTime.now();
    this.networkId = generateNetworkId(network);
    this.connectivity = AddressFamily.V4V6;
  }

  /** Getter method for the Network. */
  public Network getNetwork() {
    return network;
  }

  /** Getter method for the NetworkType. */
  public NetworkType getNetworkType() {
    return networkType;
  }

  /** Getter method for the creation time. */
  public DateTime getCreationTime() {
    return creationTime;
  }

  /** Getter method for the creation timestamp in epoch milliseconds since 1970-01-01T00:00:00Z. */
  public long getCreationTimestamp() {
    return creationTime.getMillis();
  }

  /** Gets a unique, opaque ID associated with the network. */
  public long getNetworkId() {
    return networkId;
  }

  public AddressFamily getAddressFamily() {
    return connectivity;
  }

  public void setConnectivity(AddressFamily connectivity) {
    this.connectivity = connectivity;
  }

  @Override
  public boolean equals(Object otherPpnNetwork) {
    if (!(otherPpnNetwork instanceof PpnNetwork)) {
      return false;
    }
    return this.network.equals(((PpnNetwork) otherPpnNetwork).getNetwork())
        && (this.networkType == ((PpnNetwork) otherPpnNetwork).getNetworkType());
  }

  @Override
  public int hashCode() {
    return this.network.hashCode() + this.networkType.getNumber();
  }

  @Override
  public String toString() {
    return String.format("PpnNetwork<%s> with network: %s", this.networkType.name(), this.network);
  }

  /**
   * Creates a unique, opaque ID to assign to the network. For newer Android versions, this uses the
   * network handle.
   */
  private static long generateNetworkId(Network network) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      return network.getNetworkHandle();
    } else {
      return nextNetworkId.incrementAndGet();
    }
  }
}
