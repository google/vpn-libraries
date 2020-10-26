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

package com.google.android.libraries.privacy.ppn.krypton;

import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import javax.net.SocketFactory;

/** A default implementation of BoundSocketFactoryFactory to use for tests. */
public class TestBoundSocketFactoryFactory implements BoundSocketFactoryFactory {
  @Override
  public SocketFactory withCurrentNetwork() {
    return SocketFactory.getDefault();
  }

  @Override
  public SocketFactory withNetwork(PpnNetwork ppnNetwork) {
    return SocketFactory.getDefault();
  }
}
