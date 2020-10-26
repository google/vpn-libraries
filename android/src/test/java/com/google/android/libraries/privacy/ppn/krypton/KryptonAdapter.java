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

import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnReconnectStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;

/** A simple implementation of KryptonListener with default methods. */
class KryptonAdapter implements KryptonListener {
  @Override
  public void onKryptonConnected(ConnectionStatus status) {}

  @Override
  public void onKryptonConnecting() {}

  @Override
  public void onKryptonControlPlaneConnected() {}

  @Override
  public void onKryptonStatusUpdated(ConnectionStatus status) {}

  @Override
  public void onKryptonDisconnected(PpnStatus status) {}

  @Override
  public void onKryptonNetworkFailed(PpnStatus status, NetworkInfo networkInfo) {}

  @Override
  public void onKryptonPermanentFailure(PpnStatus status) {}

  @Override
  public void onKryptonCrashed() {}

  @Override
  public void onKryptonWaitingToReconnect(PpnReconnectStatus status) {}

  @Override
  public int onKryptonNeedsTunFd(TunFdData tunFdData) throws PpnException {
    return 0;
  }

  @Override
  public void onKryptonNeedsIpSecConfiguration(IpSecTransformParams params) throws PpnException {}

  @Override
  public int onKryptonNeedsNetworkFd(NetworkInfo network) throws PpnException {
    return 0;
  }

  @Override
  public String onKryptonNeedsOAuthToken() throws PpnException {
    return null;
  }
}
