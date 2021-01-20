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

package com.google.android.libraries.privacy.ppn;

import android.accounts.Account;
import android.app.Notification;
import org.json.JSONObject;

/**
 * Ppn is the API for controlling the PPN VPN library from an Application.
 */
public interface Ppn {

  /**
   * Starts the PPN VPN service. This should only be called when the user explicitly asks to turn on
   * the VPN. If the user has turned on the "Always on" VPN feature in the Android settings, then
   * Android will start the VPN automatically, and the app does not need to call this method. To
   * stop the VPN, the caller should explicitly call {@link #stop()}.
   *
   * <p>This method is asynchronous. Once the VPN is started, {@link
   * PpnListener#onPpnStarted(Account, boolean)} will be called.
   *
   * <p>PPN will store the account so that the library can reconnect automatically if the service is
   * started while the app is closed.
   *
   * @param account the account to use for authorizing the PPN backend.
   * @throws PpnException if the service cannot be started for any reason.
   */
  void start(Account account) throws PpnException;

  /**
   * Stops the VPN service, if it is running. If the user has turned on the "Always on" VPN feature
   * in the Android system settings, then Android may try to restart the service at any time.
   *
   * <p>This method is asynchronous. Once the VPN is stopped, {@link
   * PpnListener#onPpnStopped(PpnStatus)} will be called.
   */
  void stop();

  /**
   * Updates the state of the Safe Disconnect feature. If Safe Disconnect is enabled, the network
   * will fail closed when PPN is disconnected. The default disconnection behavior without Safe
   * Disconnect is to fail-open and allow unprotected traffic.
   */
  void setSafeDisconnectEnabled(boolean enable);

  /** Returns whether Safe Disconnect is enabled in PPN. */
  boolean isSafeDisconnectEnabled();

  /** Sets a listener for PPN events, such as connection and disconnections. */
  void setPpnListener(PpnListener listener);

  /** Returns a PpnTelemetry object with data about how PPN is currently running. */
  PpnTelemetry collectTelemetry();

  /** Returns whether the PPN service is currently running. */
  boolean isRunning();

  /**
   * Sets the permanent Notification to be used for the PPN Service. Calling this multiple times
   * will change the notification. If this is called before the VpnService is running, it will be
   * saved until the service starts.
   */
  void setNotification(int notificationId, Notification notification);

  /** Returns debug info for inspecting the internal state of PPN. */
  JSONObject getDebugJson();
}
