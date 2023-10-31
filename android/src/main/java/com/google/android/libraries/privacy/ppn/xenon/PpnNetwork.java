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

import android.net.Network;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import java.util.concurrent.atomic.AtomicLong;

/** PpnNetwork used for a PpnConnection. */
public final class PpnNetwork {
  private static final AtomicLong nextCreationIndex = new AtomicLong(1);

  private final NetworkType networkType;
  private final Network network;
  private final long networkId;
  private AddressFamily connectivity;
  private final long creationIndex;

  public PpnNetwork(Network network, NetworkType networkType) {
    this.network = network;
    this.networkType = networkType;
    this.networkId = generateNetworkId(network);
    this.connectivity = AddressFamily.V4V6;
    this.creationIndex = nextCreationIndex.getAndIncrement();
  }

  public Network getNetwork() {
    return network;
  }

  public NetworkType getNetworkType() {
    return networkType;
  }

  /**
   * Gets the creation time as a counter. Generally, networks that were created more recently are
   * preferred. This is calculated using the order that the PpnNetwork constructor was invoked,
   * which is not an accurate measure of how long the network has been around. It is also not used
   * in equals, so multiple PpnNetwork instances for the same network may have different times.
   *
   * <p>TODO: Remove time from network selection logic.
   */
  public long getCreationIndex() {
    return creationIndex;
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
    return network.getNetworkHandle();
  }
}
