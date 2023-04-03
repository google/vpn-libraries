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

package com.google.android.libraries.privacy.ppn.krypton;

import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectingStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.PpnStatusDetails;
import com.google.android.libraries.privacy.ppn.internal.ReconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ResumeStatus;
import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;

/**
 * A Java wrapper around KryptonNotification, for triggering events to test JNI methods that call
 * back into Java from C++.
 */
public class JniTestNotification {
  static {
    // Even if the Krypton class isn't loaded, this class needs the C++ library loaded.
    System.loadLibrary("krypton_jni");
  }

  // Methods defined in jni_test_notification.cc.
  // LINT.IfChange
  public native void connectedNative(Krypton krypton, byte[] connectionStatusBytes)
      throws KryptonException;

  public native void connectingNative(Krypton krypton, byte[] connectingStatusBytes)
      throws KryptonException;

  public native void controlPlaneConnected(Krypton krypton) throws KryptonException;

  public native void statusUpdatedNative(Krypton krypton, byte[] connectionStatusBytes)
      throws KryptonException;

  private native void disconnectedNative(Krypton krypton, byte[] disconnectionStatusBytes)
      throws KryptonException;

  private native void permanentFailureNative(
      Krypton krypton, int code, String message, byte[] detailBytes) throws KryptonException;

  private native void waitingToReconnectNative(Krypton krypton, byte[] reconnectionStatusBytes)
      throws KryptonException;

  private native void networkDisconnectedNative(
      Krypton krypton, byte[] networkInfoBytes, int code, String message, byte[] detailBytes)
      throws KryptonException;

  public native void snoozedNative(Krypton krypton, byte[] snoozeStatusBytes)
      throws KryptonException;

  public native void resumedNative(Krypton krypton, byte[] resumeStatusBytes)
      throws KryptonException;

  private native int createSockFdTestOnlyNative();

  private native int createTunFdNative(Krypton krypton, byte[] tunFdBytes) throws KryptonException;

  private native int createNetworkFdNative(Krypton krypton, byte[] networkInfoBytes)
      throws KryptonException;

  private native int createTcpFdNative(Krypton krypton, byte[] networkInfoBytes)
      throws KryptonException;

  private native boolean configureIpSecNative(Krypton krypton, byte[] ipSecTransformParamsBytes)
      throws KryptonException;

  // LINT.ThenChange(//depot/google3/privacy/net/krypton/jni/jni_test_notification.cc)

  public void connected(Krypton krypton, ConnectionStatus status) throws KryptonException {
    connectedNative(krypton, status.toByteArray());
  }

  public void connecting(Krypton krypton, ConnectingStatus status) throws KryptonException {
    connectingNative(krypton, status.toByteArray());
  }

  public void statusUpdate(Krypton krypton, ConnectionStatus status) throws KryptonException {
    statusUpdatedNative(krypton, status.toByteArray());
  }

  public void disconnected(Krypton krypton, DisconnectionStatus status) throws KryptonException {
    disconnectedNative(krypton, status.toByteArray());
  }

  public void permanentFailure(Krypton krypton, PpnStatus status) throws KryptonException {
    PpnStatusDetails details =
        PpnStatusDetails.newBuilder()
            .setDetailedErrorCode(
                PpnStatusDetails.DetailedErrorCode.forNumber(
                    status.getDetailedErrorCode().getCode()))
            .build();
    permanentFailureNative(
        krypton, status.getCode().getCode(), status.getMessage(), details.toByteArray());
  }

  public void waitingToReconnect(Krypton krypton, ReconnectionStatus status)
      throws KryptonException {
    waitingToReconnectNative(krypton, status.toByteArray());
  }

  public void networkDisconnected(Krypton krypton, NetworkInfo networkInfo, PpnStatus status)
      throws KryptonException {
    PpnStatusDetails details =
        PpnStatusDetails.newBuilder()
            .setDetailedErrorCode(
                PpnStatusDetails.DetailedErrorCode.forNumber(
                    status.getDetailedErrorCode().getCode()))
            .build();
    networkDisconnectedNative(
        krypton,
        networkInfo.toByteArray(),
        status.getCode().getCode(),
        status.getMessage(),
        details.toByteArray());
  }

  public void snoozed(Krypton krypton, SnoozeStatus status) throws KryptonException {
    snoozedNative(krypton, status.toByteArray());
  }

  public void resumed(Krypton krypton, ResumeStatus status) throws KryptonException {
    resumedNative(krypton, status.toByteArray());
  }

  public int createSockFdTestOnly() {
    return createSockFdTestOnlyNative();
  }

  public int createTunFd(Krypton krypton, TunFdData tunFdData) throws KryptonException {
    return createTunFdNative(krypton, tunFdData.toByteArray());
  }

  public int createNetworkFd(Krypton krypton, NetworkInfo networkInfo) throws KryptonException {
    return createNetworkFdNative(krypton, networkInfo.toByteArray());
  }

  public int createTcpFd(Krypton krypton, NetworkInfo networkInfo) throws KryptonException {
    return createTcpFdNative(krypton, networkInfo.toByteArray());
  }

  public boolean configureIpSec(Krypton krypton, IpSecTransformParams params)
      throws KryptonException {
    return configureIpSecNative(krypton, params.toByteArray());
  }
}
