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
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectingStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.ReconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ResumeStatus;
import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;

/** A simple implementation of KryptonListener with default methods. */
class KryptonAdapter implements KryptonListener {
  @Override
  public void onKryptonConnected(ConnectionStatus status) {}

  @Override
  public void onKryptonConnecting(ConnectingStatus connectingStatus) {}

  @Override
  public void onKryptonControlPlaneConnected() {}

  @Override
  public void onKryptonStatusUpdated(ConnectionStatus status) {}

  @Override
  public void onKryptonDisconnected(DisconnectionStatus disconnectionStatus) {}

  @Override
  public void onKryptonNetworkFailed(PpnStatus status, NetworkInfo networkInfo) {}

  @Override
  public void onKryptonPermanentFailure(PpnStatus status) {}

  @Override
  public void onKryptonCrashed() {}

  @Override
  public void onKryptonWaitingToReconnect(ReconnectionStatus status) {}

  @Override
  public void onKryptonSnoozed(SnoozeStatus status) {}

  @Override
  public void onKryptonResumed(ResumeStatus status) {}

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
}
