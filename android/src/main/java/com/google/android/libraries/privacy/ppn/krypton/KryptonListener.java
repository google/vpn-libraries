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

/** Notification of events from Krypton. */
public interface KryptonListener {
  /**
   * Called when the PPN data plane connects to the backend.
   *
   * @param status metadata about the connection.
   */
  void onKryptonConnected(ConnectionStatus status);

  /**
   * Called when Krypton starts trying to establish a new session.
   *
   * @param status Information about the state of PPN while connecting.
   */
  void onKryptonConnecting(ConnectingStatus status);

  /** Called when the PPN control plane connects to the backend. */
  void onKryptonControlPlaneConnected();

  /** Called to update Krypton clients with metadata about the data connection. */
  void onKryptonStatusUpdated(ConnectionStatus status);

  /**
   * Called when the PPN data plane disconnects from the backend.
   *
   * @param status Information about the disconnection.
   */
  void onKryptonDisconnected(DisconnectionStatus status);

  /** Called when Krypton decides the current network has failed. */
  void onKryptonNetworkFailed(PpnStatus status, NetworkInfo networkInfo);

  /** Called whenever Krypton cannot continue. Clients receiving this event must call stop(). */
  void onKryptonPermanentFailure(PpnStatus status);

  /** Called whenever Krypton intercepts a signal that means the app is crashing. */
  void onKryptonCrashed();

  /**
   * Called when Krypton starts a reconnection sequence. Passes a PpnReconnectStatus to PPN
   * containing the time until the next connection attempt.
   */
  void onKryptonWaitingToReconnect(ReconnectionStatus status);

  /** Called when Krypton is snoozed. */
  void onKryptonSnoozed(SnoozeStatus status);

  /** Called when Krypton is resumed. */
  void onKryptonResumed(ResumeStatus disconnectionStatus);

  /**
   * Called by Krypton whenever it needs the VPN service to establish new TUN fds.
   *
   * @param tunFdData tunFdData needed for creating the TunFd.
   */
  int onKryptonNeedsTunFd(TunFdData tunFdData) throws PpnException;

  void onKryptonNeedsIpSecConfiguration(IpSecTransformParams params) throws PpnException;

  /**
   * Called by Krypton whenever it needs a new network fd.
   *
   * @param network the network the fd should be bound to.
   */
  int onKryptonNeedsNetworkFd(NetworkInfo network) throws PpnException;

  /**
   * Called by Krypton whenever it needs a new TCP/IP network fd.
   *
   * @param network the network the fd should be bound to.
   */
  int onKryptonNeedsTcpFd(NetworkInfo network) throws PpnException;
}
