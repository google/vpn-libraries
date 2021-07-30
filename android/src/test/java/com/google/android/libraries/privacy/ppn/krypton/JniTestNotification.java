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
  public native void connectedNative(byte[] connectionStatusBytes) throws KryptonException;

  public native void connectingNative(byte[] connectingStatusBytes) throws KryptonException;

  public native void controlPlaneConnected() throws KryptonException;

  public native void statusUpdatedNative(byte[] connectionStatusBytes) throws KryptonException;

  private native void disconnectedNative(byte[] disconnectionStatusBytes) throws KryptonException;

  private native void permanentFailureNative(int code, String message, byte[] detailBytes)
      throws KryptonException;

  private native void waitingToReconnectNative(byte[] reconnectionStatusBytes)
      throws KryptonException;

  private native void networkDisconnectedNative(
      byte[] networkInfoBytes, int code, String message, byte[] detailBytes)
      throws KryptonException;

  public native void snoozedNative(byte[] snoozeStatusBytes) throws KryptonException;

  public native void resumedNative(byte[] resumeStatusBytes) throws KryptonException;

  private native int createTunFdNative(byte[] tunFdBytes) throws KryptonException;

  private native int createNetworkFdNative(byte[] networkInfoBytes) throws KryptonException;

  private native boolean configureIpSecNative(byte[] ipSecTransformParamsBytes)
      throws KryptonException;

  public native String getOAuthToken() throws KryptonException;
  // LINT.ThenChange(//depot/google3/privacy/net/krypton/jni/jni_test_notification.cc)

  public void connected(ConnectionStatus status) throws KryptonException {
    connectedNative(status.toByteArray());
  }

  public void connecting(ConnectingStatus status) throws KryptonException {
    connectingNative(status.toByteArray());
  }

  public void statusUpdate(ConnectionStatus status) throws KryptonException {
    statusUpdatedNative(status.toByteArray());
  }

  public void disconnected(DisconnectionStatus status) throws KryptonException {
    disconnectedNative(status.toByteArray());
  }

  public void permanentFailure(PpnStatus status) throws KryptonException {
    PpnStatusDetails details =
        PpnStatusDetails.newBuilder()
            .setDetailedErrorCode(
                PpnStatusDetails.DetailedErrorCode.forNumber(
                    status.getDetailedErrorCode().getCode()))
            .build();
    permanentFailureNative(status.getCode().getCode(), status.getMessage(), details.toByteArray());
  }

  public void waitingToReconnect(ReconnectionStatus status) throws KryptonException {
    waitingToReconnectNative(status.toByteArray());
  }

  public void networkDisconnected(NetworkInfo networkInfo, PpnStatus status)
      throws KryptonException {
    PpnStatusDetails details =
        PpnStatusDetails.newBuilder()
            .setDetailedErrorCode(
                PpnStatusDetails.DetailedErrorCode.forNumber(
                    status.getDetailedErrorCode().getCode()))
            .build();
    networkDisconnectedNative(
        networkInfo.toByteArray(),
        status.getCode().getCode(),
        status.getMessage(),
        details.toByteArray());
  }

  public void snoozed(SnoozeStatus status) throws KryptonException {
    snoozedNative(status.toByteArray());
  }

  public void resumed(ResumeStatus status) throws KryptonException {
    resumedNative(status.toByteArray());
  }

  public int createTunFd(TunFdData tunFdData) throws KryptonException {
    return createTunFdNative(tunFdData.toByteArray());
  }

  public int createNetworkFd(NetworkInfo networkInfo) throws KryptonException {
    return createNetworkFdNative(networkInfo.toByteArray());
  }

  public boolean configureIpSec(IpSecTransformParams params) throws KryptonException {
    return configureIpSecNative(params.toByteArray());
  }
}
