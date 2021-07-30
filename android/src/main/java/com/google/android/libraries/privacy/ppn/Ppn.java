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
import com.google.common.util.concurrent.ListenableFuture;
import java.time.Duration;
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
   * <p>This method is asynchronous. It can be called from any thread. Once the VPN is started,
   * {@link PpnListener#onPpnStarted(Account, boolean)} will be called. This method cannot fail in
   * any way that can be handled by callers.
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
   * <p>This method is asynchronous, and can be called from any thread. Once the VPN is stopped,
   * {@link PpnListener#onPpnStopped(PpnStatus)} will be called. This method cannot fail in any way
   * that can be handled by callers.
   */
  void stop();

  /**
   * Restarts PPN to pick up the updated set of apps that will bypass the VPN. This does not fully
   * stop the VPN service, it disconnects Krypton and recreates the tunnel.
   *
   * <p>This method is asynchronous, and can be called from any thread.
   */
  ListenableFuture<Void> restart();

  /**
   * Temporarily disconnects PPN and closes the VPN tunnel, if it is running.
   *
   * <p>This is different from stop in that the VPN service continues to run. After a certain amount
   * of time or if resume is called before that time, the connection is resumed. This method is
   * asynchronous, and can be called from any thread. The returned future is primarily for knowing
   * if an error occurred. PpnListeners will receive the onPpnSnoozed event once the snooze has
   * started, at which time calling resume will become valid.
   */
  ListenableFuture<Void> snooze(Duration snoozeDuration);

  /**
   * Tells PPN to re-establish its tunnel and start trying to connect, if it is snoozed.
   *
   * <p>This does not start the VPN service but will re-open the tunnel if previously snoozed. This
   * method is asynchronous, and can be called from any thread. The returned future is primarily for
   * knowing if an error occurred. PpnListeners will receive the onPpnResumed event once the snooze
   * has ended, at which time calling snooze will become valid again.
   */
  ListenableFuture<Void> resume();

  /** Extends the duration of snooze. */
  ListenableFuture<Void> extendSnooze(Duration extendDuration);

  /**
   * Updates the state of the Safe Disconnect feature. If Safe Disconnect is enabled, the network
   * will fail closed when PPN is disconnected. The default disconnection behavior without Safe
   * Disconnect is to fail-open and allow unprotected traffic.
   *
   * <p>This is an async method, and can be called from any thread.
   */
  ListenableFuture<Void> setSafeDisconnectEnabled(boolean enable);

  /**
   * Updates the set of apps that will bypass the VPN, as package names. This will take effect the
   * next time {@link Ppn#start(Account)} is called.
   *
   * <p>This method can be called from any thread.
   */
  void setDisallowedApplications(Iterable<String> disallowedApplications);

  /** Returns whether Safe Disconnect is enabled in PPN. Can be called from any thread. */
  boolean isSafeDisconnectEnabled();

  /**
   * Sets a listener for PPN events, such as connection and disconnections.
   *
   * <p>This method can be called from any thread.
   */
  void setPpnListener(PpnListener listener);

  /**
   * Returns a PpnTelemetry object with data about how PPN is currently running.
   *
   * <p>This is a blocking call, and should be called from a background thread.
   */
  PpnTelemetry collectTelemetry();

  /** Returns whether the PPN service is currently running. Can be called from any thread. */
  boolean isRunning();

  /**
   * Sets the permanent Notification to be used for the PPN Service. Calling this multiple times
   * will change the notification. If this is called before the VpnService is running, it will be
   * saved until the service starts. This method can be called from any thread.
   */
  void setNotification(int notificationId, Notification notification);

  /**
   * Puts Krypton in a horrible wedged state, for testing app bypass, etc.
   *
   * <p>This is an async method, and can be called from any thread.
   */
  ListenableFuture<Void> setSimulatedNetworkFailure(boolean simulatedNetworkFailure);
  /**
   * Returns debug info for inspecting the internal state of PPN.
   *
   * <p>This is a blocking call, and it can block the calling thread indefinitely, waiting on
   * Krypton's internal locks. So, it should be called on a background thread.
   */
  JSONObject getDebugJson();
}
