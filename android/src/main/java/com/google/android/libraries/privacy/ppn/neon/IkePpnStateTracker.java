/*
 * Copyright (C) 2023 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.libraries.privacy.ppn.neon;

import android.accounts.Account;
import android.annotation.TargetApi;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.PpnConnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnDisconnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnListener;
import com.google.android.libraries.privacy.ppn.PpnResumeStatus;
import com.google.android.libraries.privacy.ppn.PpnSnoozeStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ResumeStatus;
import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;

/**
 * A state tracker for the state of VpnManager-based PPN. The VpnManager-based PPN is not running
 * all the time, so this class is used to persist state from run to run.
 */
@TargetApi(33)
public class IkePpnStateTracker {
  /**
   * VpnManager-based PPN internal state that used to record all detail states for PPN life cycle
   */
  public enum VpnInternalState {
    STOPPED,
    PROVISIONING,
    PROVISION_FAILED,
    WAITING_REPROVISION,
    CONNECTING,
    DISCONNECTED,
    CONNECTED,
    PAUSED,
    FAILED,
  }

  /** VpnManager-based PPN external state that used to update PPN UI */
  public enum VpnExternalState {
    STOPPED,
    CONNECTED,
    DISCONNECTED,
    PAUSED,
  }

  private static final String TAG = "IkePpnStateTracker";
  private static final Object lock = new Object();
  private static IkePpnStateTracker instance = null;
  private VpnExternalState vpnExternalState;
  private VpnInternalState vpnInternalState;

  @Nullable private PpnListener listener;
  private final Handler mainHandler = new Handler(Looper.getMainLooper());

  /**
   * Gets the IkePpnStateTracker singleton instance. There is only one VPN profile installed for
   * apps that use PPN, so it just has the one global state.
   */
  public static IkePpnStateTracker getInstance() {
    synchronized (lock) {
      if (instance == null) {
        instance = new IkePpnStateTracker();
      }
      return instance;
    }
  }

  private IkePpnStateTracker() {
    vpnInternalState = VpnInternalState.STOPPED;
    vpnExternalState = VpnExternalState.STOPPED;
  }

  /** Function to return VpnManager-based PPN external state */
  public VpnExternalState getVpnExternalState() {
    synchronized (lock) {
      return vpnExternalState;
    }
  }

  /** Function to return VpnManager-based PPN internal state */
  public VpnInternalState getVpnInternalState() {
    synchronized (lock) {
      return vpnInternalState;
    }
  }

  /**
   * Function to set PpnListener to IkePpnStateTracker.
   *
   * @param listener A listener for PPN events, such as connection and disconnection.
   */
  public void setListener(PpnListener listener) {
    synchronized (lock) {
      this.listener = listener;
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN is started.
   *
   * <p>This function should be called when VpnManager-based PPN is started either by end user
   * manually or by system when VPN Always On is enabled.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   *
   * @param account The Account used to authenticate PPN.
   */
  public void setStarted(Account account) {
    synchronized (lock) {
      Log.v(TAG, "setStarted()");
      vpnInternalState = VpnInternalState.PROVISIONING;
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnStarted(account, true);
        onPpnDisconnected();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN is stopped.
   *
   * <p>This function should be called when VpnManager-based PPN is stopped either by end user
   * manually or by system when event VpnManager.CATEGORY_EVENT_DEACTIVATED_BY_USER is received.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   *
   * @param status The status that PPN should report to the Ppnlistener when it is finished
   *     stopping.
   */
  public void setStopped(PpnStatus status) {
    synchronized (lock) {
      Log.v(TAG, "setStopped()");
      vpnInternalState = VpnInternalState.STOPPED;
      vpnExternalState = VpnExternalState.STOPPED;
      onPpnStopped(status);
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN provision finished successfully.
   *
   * <p>This function should be called when Provision.Listener.onProvisioned() get called.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setProvisioned() {
    synchronized (lock) {
      Log.v(TAG, "setProvisioned()");
      vpnInternalState = VpnInternalState.CONNECTING;
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnDisconnected();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN provision failed.
   *
   * <p>This function should be called when Provision.Listener.onProvisioningFailure() get called.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   *
   * @param status The status that PPN should report to the Ppnlistener when provision failed.
   * @param permanent True if the provision failure is permanent, or false if it is transient.
   */
  public void setProvisionFailed(PpnStatus status, boolean permanent) {
    synchronized (lock) {
      Log.v(TAG, "setProvisionFailed()");
      if (permanent) {
        vpnInternalState = VpnInternalState.PROVISION_FAILED;
      } else {
        vpnInternalState = VpnInternalState.WAITING_REPROVISION;
      }
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnDisconnected();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN connected successfully.
   *
   * <p>This function should be called when the VPN network is connected and validated successfully.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setConnected() {
    synchronized (lock) {
      Log.v(TAG, "setConnected()");
      vpnInternalState = VpnInternalState.CONNECTED;
      if (vpnExternalState != VpnExternalState.CONNECTED) {
        vpnExternalState = VpnExternalState.CONNECTED;
        onPpnConnected();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN disconnected.
   *
   * <p>This function should be called when the VPN network capabilities updated to a disconnected
   * state, or any VpnManager.ERROR_CLASS_RECOVERABLE error received by VpnManager.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setDisconnected() {
    synchronized (lock) {
      Log.v(TAG, "setDisconnected()");
      if (vpnInternalState != VpnInternalState.FAILED
          && vpnInternalState != VpnInternalState.PROVISION_FAILED) {
        vpnInternalState = VpnInternalState.DISCONNECTED;
      }
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnDisconnected();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN is paused.
   *
   * <p>This function should be called when the VPN is paused manually by end user.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setPaused() {
    synchronized (lock) {
      Log.v(TAG, "setPaused()");
      vpnInternalState = VpnInternalState.PAUSED;
      if (vpnExternalState != VpnExternalState.PAUSED) {
        vpnExternalState = VpnExternalState.PAUSED;
        onPpnPaused();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN is resumed.
   *
   * <p>This function should be called when the VPN is resumed from a paused state.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setResumed() {
    synchronized (lock) {
      Log.v(TAG, "setResumed()");
      vpnInternalState = VpnInternalState.DISCONNECTED;
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnResumed();
      }
    }
  }

  /**
   * Function to update VpnManager-based PPN state when VPN failed to connect.
   *
   * <p>This function should be called when any VpnManager.ERROR_CLASS_NOT_RECOVERABLE error
   * received by VpnManager.
   *
   * <p>Calling this function incorrectly would cause incorrect UI get displayed and incorrect VPN
   * state get recorded.
   */
  public void setFailed() {
    synchronized (lock) {
      Log.v(TAG, "setFailed()");
      vpnInternalState = VpnInternalState.FAILED;
      if (vpnExternalState != VpnExternalState.DISCONNECTED) {
        vpnExternalState = VpnExternalState.DISCONNECTED;
        onPpnDisconnected();
      }
    }
  }

  private void onPpnStarted(Account account, boolean needsNotification) {
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnStarted(account, needsNotification);
          }
        });
  }

  private void onPpnStopped(PpnStatus status) {
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnStopped(status);
          }
        });
  }

  private void onPpnConnected() {
    // TODO: Add network details, if possible.
    ConnectionStatus proto = ConnectionStatus.getDefaultInstance();
    PpnConnectionStatus status;
    try {
      status = PpnConnectionStatus.fromProto(proto);
    } catch (PpnException e) {
      Log.e(TAG, "Unable to build ConnectionStatus", e);
      return;
    }
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnConnected(status);
          }
        });
  }

  private void onPpnDisconnected() {
    // TODO: Add network details, if possible.
    DisconnectionStatus proto = DisconnectionStatus.getDefaultInstance();
    PpnDisconnectionStatus disconnectionStatus = PpnDisconnectionStatus.fromProto(proto);
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnDisconnected(disconnectionStatus);
          }
        });
  }

  private void onPpnPaused() {
    SnoozeStatus proto = SnoozeStatus.getDefaultInstance();
    PpnSnoozeStatus snoozeStatus = PpnSnoozeStatus.fromProto(proto);
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnSnoozed(snoozeStatus);
          }
        });
  }

  private void onPpnResumed() {
    ResumeStatus proto = ResumeStatus.getDefaultInstance();
    PpnResumeStatus resumeStatus = PpnResumeStatus.fromProto(proto);
    mainHandler.post(
        () -> {
          if (listener != null) {
            listener.onPpnResumed(resumeStatus);
          }
        });
  }
}
