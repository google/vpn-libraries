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

package com.google.android.libraries.privacy.ppn.internal.service;

import com.google.android.libraries.privacy.ppn.internal.http.BoundSocketFactoryFactory;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import javax.net.SocketFactory;

/** A BoundSocketFactoryFactory that produces ProtectedSocketFactory instances. */
public class ProtectedSocketFactoryFactory implements BoundSocketFactoryFactory {
  private final VpnManager vpnManager;

  public ProtectedSocketFactoryFactory(VpnManager vpnManager) {
    this.vpnManager = vpnManager;
  }

  /** Creates a new factory based on this one, but with the current network at time of use. */
  @Override
  public SocketFactory withCurrentNetwork() {
    return new ProtectedSocketFactory(vpnManager, vpnManager::getNetwork);
  }

  /** Creates a new factory based on this one, but with the given network hard-coded. */
  @Override
  public SocketFactory withNetwork(PpnNetwork network) {
    return new ProtectedSocketFactory(vpnManager, () -> network);
  }
}
