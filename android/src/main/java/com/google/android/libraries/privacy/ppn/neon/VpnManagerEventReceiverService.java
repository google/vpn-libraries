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

import android.annotation.TargetApi;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnManager;
import android.net.VpnProfileState;
import android.os.IBinder;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.PpnStatus;

/** Service to receive VpnManager events. */
@TargetApi(33)
public final class VpnManagerEventReceiverService extends Service {

  private static final String TAG = "VpnManagerEvent";

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    Log.v(TAG, "onStartCommand()");
    if (intent == null) {
      Log.v(TAG, "Intent is null");
      return super.onStartCommand(intent, flags, startId);
    }

    if (intent.getCategories() == null) {
      Log.v(TAG, "Categories is null.");
      return super.onStartCommand(intent, flags, startId);
    }

    int errorClass = intent.getIntExtra(VpnManager.EXTRA_ERROR_CLASS, /* defaultValue= */ 0);
    boolean permanent = (errorClass == VpnManager.ERROR_CLASS_NOT_RECOVERABLE);
    int errorCode = intent.getIntExtra(VpnManager.EXTRA_ERROR_CODE, /* defaultValue= */ 0);
    VpnProfileState profileState = intent.getParcelableExtra(VpnManager.EXTRA_VPN_PROFILE_STATE);
    String sessionKey = intent.getStringExtra(VpnManager.EXTRA_SESSION_KEY);
    Network network = intent.getParcelableExtra(VpnManager.EXTRA_UNDERLYING_NETWORK);
    LinkProperties linkProperties =
        intent.getParcelableExtra(VpnManager.EXTRA_UNDERLYING_LINK_PROPERTIES);
    NetworkCapabilities networkCapabilities =
        intent.getParcelableExtra(VpnManager.EXTRA_UNDERLYING_NETWORK_CAPABILITIES);
    VpnManager vpnManager =
        (VpnManager) getApplicationContext().getSystemService(Context.VPN_MANAGEMENT_SERVICE);

    if (intent.getCategories().contains(VpnManager.CATEGORY_EVENT_IKE_ERROR)) {
      Log.v(TAG, "onStartCommand(): CATEGORY_EVENT_IKE_ERROR");
      if (errorClass == VpnManager.ERROR_CLASS_RECOVERABLE) {
        IkePpnStateTracker.getInstance().setDisconnected();
      } else {
        IkePpnStateTracker.getInstance().setFailed();
      }
    } else if (intent.getCategories().contains(VpnManager.CATEGORY_EVENT_DEACTIVATED_BY_USER)) {
      Log.v(TAG, "onStartCommand(): CATEGORY_EVENT_DEACTIVATED_BY_USER");
      IkePpnStateTracker.getInstance().setStopped(PpnStatus.STATUS_OK);
    } else if (intent.getCategories().contains(VpnManager.CATEGORY_EVENT_ALWAYS_ON_STATE_CHANGED)) {
      Log.v(TAG, "onStartCommand(): CATEGORY_EVENT_ALWAYS_ON_STATE_CHANGED");
    } else if (intent.getCategories().contains(VpnManager.CATEGORY_EVENT_NETWORK_ERROR)) {
      Log.v(TAG, "onStartCommand(): CATEGORY_EVENT_NETWORK_ERROR");
      IkePpnStateTracker.getInstance().setDisconnected();
    } else {
      Log.v(TAG, "onStartCommand(): CATEGORY_UNKNOWN");
    }
    Log.v(
        TAG,
        "onStartCommand() current profileState: "
            + vpnManager.getProvisionedVpnProfileState()
            + ", profileState : "
            + profileState
            + ", errorClass : "
            + getErrorClass(errorClass)
            + ", errorCode : "
            + getErrorCode(errorCode)
            + ", network : "
            + network
            + ", linkProperties : "
            + linkProperties
            + ", networkCapabilities : "
            + networkCapabilities
            + ", sessionKey : "
            + sessionKey
            + ", permanent : "
            + permanent);
    return super.onStartCommand(intent, flags, startId);
  }

  private String getErrorClass(int errorClass) {
    if (errorClass == VpnManager.ERROR_CLASS_NOT_RECOVERABLE) {
      return "ERROR_CLASS_NOT_RECOVERABLE";
    } else if (errorClass == VpnManager.ERROR_CLASS_RECOVERABLE) {
      return "ERROR_CLASS_RECOVERABLE";
    } else if (errorClass == -1) {
      return "-1";
    } else {
      return "Unknown error class: " + errorClass;
    }
  }

  private String getErrorCode(int errorCode) {
    if (errorCode == VpnManager.ERROR_CODE_NETWORK_IO) {
      return "ERROR_CODE_NETWORK_IO";
    } else if (errorCode == VpnManager.ERROR_CODE_NETWORK_LOST) {
      return "ERROR_CODE_NETWORK_LOST";
    } else if (errorCode == VpnManager.ERROR_CODE_NETWORK_PROTOCOL_TIMEOUT) {
      return "ERROR_CODE_NETWORK_PROTOCOL_TIMEOUT";
    } else if (errorCode == VpnManager.ERROR_CODE_NETWORK_UNKNOWN_HOST) {
      return "ERROR_CODE_NETWORK_UNKNOWN_HOST";
    } else if (errorCode == -1) {
      return "-1";
    } else {
      return "Unknown error code: " + errorCode;
    }
  }

  @Nullable
  @Override
  public IBinder onBind(Intent intent) {
    return null;
  }
}
