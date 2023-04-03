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

package com.google.android.libraries.privacy.ppn;

import android.accounts.Account;

/** A listener for PPN events, such as connection and disconnections. */
public interface PpnListener {

  /**
   * Called when the PPN Service is started.
   *
   * @param account The Account used to authenticate PPN.
   * @param needsNotification Whether the client needs to call setNotification.
   */
  void onPpnStarted(Account account, boolean needsNotification);

  /**
   * Called when the PPN Service stops.
   *
   * @param status The reason for stopping.
   */
  default void onPpnStopped(PpnStatus status) {}

  /** Called whenever PPN connects. */
  default void onPpnConnected(PpnConnectionStatus status) {}

  /** Called periodically by PPN to report changes in network state. */
  default void onPpnStatusUpdated(PpnConnectionStatus status) {}

  /**
   * Called whenever PPN has disconnected, whether through explicit user action, or because it was
   * unreachable over the network.
   *
   * @param status Information about the disconnection state.
   */
  default void onPpnDisconnected(PpnDisconnectionStatus status) {}

  /**
   * Called when PPN starts trying to connect.
   *
   * @param connectingStatus Information about the state of PPN while it's trying to connect.
   */
  default void onPpnConnecting(PpnConnectingStatus connectingStatus) {}

  /**
   * Called when PPN decides it is going to wait for a period of time before trying to connect.
   *
   * @param reconnectionStatus Information about the state of PPN.
   */
  default void onPpnWaitingToReconnect(PpnReconnectionStatus reconnectionStatus) {}

  /**
   * Called whenever PPN is snoozed.
   *
   * @param snoozeStatus Information about how PPN is snoozing.
   */
  default void onPpnSnoozed(PpnSnoozeStatus snoozeStatus) {}

  /**
   * Called whenever PPN is resumed and is ready to be snoozed again.
   *
   * @param resumeStatus Information about PPN's status now that it's resumed.
   */
  default void onPpnResumed(PpnResumeStatus resumeStatus) {}
}
