// Copyright 2022 Google LLC
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

package com.google.android.libraries.privacy.ppn.neon;

import android.net.Network;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.internal.http.BoundSocketFactoryFactory;
import javax.net.SocketFactory;

/** A BoundSocketFactoryFactory for use with Provision. */
public class ProvisionSocketFactoryFactory implements BoundSocketFactoryFactory {
  @Nullable private final Network network;

  public ProvisionSocketFactoryFactory(@Nullable Network network) {
    this.network = network;
  }

  /** Creates a new factory based on this one, but with the current network at time of use. */
  @Override
  public SocketFactory withCurrentNetwork() {
    return new ProvisionSocketFactory(network);
  }

  /** Creates a new factory based on this one, but with the given network hard-coded. */
  @Override
  public SocketFactory withNetwork(Network otherNetwork) {
    return new ProvisionSocketFactory(otherNetwork);
  }
}
