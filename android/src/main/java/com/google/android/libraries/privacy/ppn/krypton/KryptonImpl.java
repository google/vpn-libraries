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

import android.support.annotation.VisibleForTesting;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnReconnectStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import com.google.android.libraries.privacy.ppn.internal.KryptonDebugInfo;
import com.google.android.libraries.privacy.ppn.internal.KryptonTelemetry;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.time.Duration;
import java.util.concurrent.Executor;
import org.json.JSONObject;

/**
 * Interface to Krypton native library.
 *
 * <p>To start handling VPN traffic, call start(). When it's time to stop the VPN service, callers
 * must call stop() to close any open file descriptors and free memory used by Krypton. All
 * lifecycle events for Krypton will be reported by the provided KryptonListener.
 */
public class KryptonImpl implements Krypton, TimerListener {
  private static final String TAG = "Krypton";
  private static final String NATIVE_TAG = "KryptonNative";

  static {
    System.loadLibrary("krypton_jni");
  }

  private final KryptonListener listener;
  private final HttpFetcher httpFetcher;
  private final Executor backgroundExecutor;
  private final TimerIdManager timerIdManager;

  /**
   * Initializes a Krypton instance with the given parameters.
   *
   * @param kryptonListener The listener to callback with events from Krypton.
   * @param backgroundExecutor An executor to use for any background work Krypton needs to do.
   */
  public KryptonImpl(
      HttpFetcher httpFetcher, KryptonListener kryptonListener, Executor backgroundExecutor) {
    this.httpFetcher = httpFetcher;
    this.listener = kryptonListener;
    this.backgroundExecutor = backgroundExecutor;
    this.timerIdManager = new TimerIdManager(this);
  }

  // Native methods, implemented in krypton_jni.cc
  // LINT.IfChange

  /** Initializes this Krypton instances as the shared singleton for C++. */
  @VisibleForTesting
  native void init() throws KryptonException;

  /**
   * Starts Krypton running in the background.
   *
   * <p>Implemented in the native library |Krypton::Start|.
   *
   * @param configBytes a serialized KryptonConfig proto.
   */
  private native void startNative(byte[] configBytes) throws KryptonException;

  /**
   * Stops the Krypton service, closing any open connections.
   *
   * <p>Implemented in the native library |Krypton::Stop|
   */
  @Override
  public native void stop() throws KryptonException;

  /**
   * Switches the outgoing network for PPN.
   *
   * <p>Implemented in the native library |Krypton::SetNetwork|
   *
   * @param networkInfoBytes a serialized NetworkInfo proto
   */
  private native void setNetworkNative(byte[] networkInfoBytes) throws KryptonException;

  /**
   * Indicates that no networks are available. The behavior of Krypton could be Fail Open or Fail
   * Closed.
   *
   * <p>Implemented by the native library in |Krypton::SetNoNetworkAvailable|
   */
  @Override
  public native void setNoNetworkAvailable() throws KryptonException;

  // Native method for timer expiry.
  private native void timerExpired(int timerId);

  // Native method for Pause
  @Override
  public native void pause(int durationMilliseconds) throws KryptonException;

  /**
   * Sets the state of the Safe Disconnect feature in Krypton.
   *
   * <p>Implemented by the native library in |Krypton::SetSafeDisconnectEnabled|
   */
  @Override
  public native void setSafeDisconnectEnabled(boolean enable) throws KryptonException;

  /**
   * Returns whether Safe Disconnect is enabled in Krypton.
   *
   * <p>Implemented by the native library in |Krypton::IsSafeDisconnectEnabled|
   */
  @Override
  public native boolean isSafeDisconnectEnabled() throws KryptonException;

  /**
   * Native method for collecting telemetry.
   *
   * @return a serialized KryptonTelemetry proto.
   */
  private native byte[] collectTelemetryNative() throws KryptonException;

  /**
   * Native method for getting debug info.
   *
   * @return a serialized KryptonDebugInfo proto.
   */
  private native byte[] getDebugInfoNative() throws KryptonException;

  // LINT.ThenChange(//depot/google3/privacy/net/krypton/jni/krypton_jni.cc)

  // Java methods, called using jni_cache.cc
  // LINT.IfChange

  // Android implementation for HTTP fetch.
  private HttpFetcher getHttpFetcher() {
    return httpFetcher;
  }

  // Android implementation for TimerIdManager.
  private TimerIdManager getTimerIdManager() {
    return timerIdManager;
  }

  // TODO: Pass the log level in here.
  private static void log(String logEntry) {
    Log.w(NATIVE_TAG, logEntry);
  }

  private void onConnected(byte[] statusBytes) {
    try {
      ConnectionStatus status =
          ConnectionStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonConnected(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  private void onConnecting() {
    listener.onKryptonConnecting();
  }

  private void onControlPlaneConnected() {
    listener.onKryptonControlPlaneConnected();
  }

  private void onStatusUpdated(byte[] statusBytes) {
    try {
      ConnectionStatus status =
          ConnectionStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonStatusUpdated(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  private void onDisconnected(int code, String reason) {
    PpnStatus status = new PpnStatus(code, reason);
    listener.onKryptonDisconnected(status);
  }

  /** Used for notifying the network that is being used has disconnected. */
  private void onNetworkFailed(byte[] networkInfoBytes, int code, String reason) {
    PpnStatus status = new PpnStatus(code, reason);
    try {
      NetworkInfo networkInfo =
          NetworkInfo.parseFrom(networkInfoBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonNetworkFailed(status, networkInfo);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to create network info.", e);
    }
  }

  private void onPermanentFailure(int code, String reason) {
    PpnStatus status = new PpnStatus(code, reason);
    // Make sure to run this asynchronously, so that stopping Krypton won't cause deadlocks.
    backgroundExecutor.execute(() -> listener.onKryptonPermanentFailure(status));
  }

  private void onCrashed() {
    listener.onKryptonCrashed();
  }

  private void onWaitingToReconnect(long retryMillis) {
    PpnReconnectStatus status = new PpnReconnectStatus(Duration.ofMillis(retryMillis));
    listener.onKryptonWaitingToReconnect(status);
  }

  /**
   * Used to call into the PPN service and establish a TUN fd. Krypton takes ownership of the
   * returned TUN fd, and is responsible for closing it.
   *
   * @return the file descriptor, or a negative value, if one could not be created.
   */
  private int createTunFd(byte[] tunFdBytes) {
    try {
      TunFdData tunFdData =
          TunFdData.parseFrom(tunFdBytes, ExtensionRegistryLite.getEmptyRegistry());
      return listener.onKryptonNeedsTunFd(tunFdData);
    } catch (PpnException | InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to create TUN fd.", e);
      return -1;
    }
  }

  /**
   * Used to call into the PPN service and create a new network fd. Krypton takes ownership of the
   * returned fd, and is responsible for closing it.
   *
   * @return the file descriptor, or a negative value, if one could not be created.
   */
  private int createNetworkFd(byte[] networkInfoBytes) {
    try {
      NetworkInfo networkInfo =
          NetworkInfo.parseFrom(networkInfoBytes, ExtensionRegistryLite.getEmptyRegistry());
      return listener.onKryptonNeedsNetworkFd(networkInfo);
    } catch (PpnException | InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to create network fd.", e);
      return -1;
    }
  }

  /**
   * Applies an IPSec transform to a network file descriptor.
   *
   * @return true if transform is successfully applied; false otherwise.
   */
  private boolean configureIpSec(byte[] ipSecTransformParamsBytes) {
    try {
      IpSecTransformParams ipSecParams =
          IpSecTransformParams.parseFrom(
              ipSecTransformParamsBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonNeedsIpSecConfiguration(ipSecParams);
      return true;
    } catch (PpnException | InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to configure IPSec.", e);
    }
    return false;
  }

  /**
   * Used to call into the PPN service to get a new OAuth token for Zinc.
   *
   * @return the token as a String, or an empty String if there was a failure.
   */
  private String getOAuthToken() {
    try {
      return listener.onKryptonNeedsOAuthToken();
    } catch (PpnException e) {
      // This method is used from C++ code, so we can't easily throw an Exception here.
      Log.e(TAG, "Unable to get Zinc oauth token.", e);
      return "";
    }
  }

  // LINT.ThenChange(//depot/google3/privacy/net/krypton/jni/jni_cache.cc)

  @Override
  public void onTimerExpired(int timerId) {
    // Timers expire on the main thread, but calls into Krypton shouldn't use the main thread.
    backgroundExecutor.execute(() -> timerExpired(timerId));
  }

  /**
   * Starts Krypton running in the background.
   *
   * <p>Implemented in the native library |Krypton::Start|.
   */
  @Override
  public void start(KryptonConfig config) throws KryptonException {
    init();
    startNative(config.toByteArray());
  }

  /**
   * Sets the outbound network of the device.
   *
   * <p>Implemented by the native library in |Krypton::SetNetwork|
   */
  @Override
  public void setNetwork(NetworkInfo request) throws KryptonException {
    setNetworkNative(request.toByteArray());
  }

  // Java method for collecting telemetry.
  @Override
  public KryptonTelemetry collectTelemetry() throws KryptonException {
    byte[] bytes = collectTelemetryNative();
    if (bytes == null) {
      throw new KryptonException("Krypton returned null telemetry bytes.");
    }
    try {
      KryptonTelemetry proto =
          KryptonTelemetry.parseFrom(bytes, ExtensionRegistryLite.getEmptyRegistry());
      return proto;
    } catch (InvalidProtocolBufferException e) {
      throw new KryptonException("Invalid telemetry proto bytes from Krypton.", e);
    }
  }

  // Java method for getting debug info.
  @Override
  public JSONObject getDebugJson() throws KryptonException {
    byte[] bytes = getDebugInfoNative();
    if (bytes == null) {
      throw new KryptonException("Krypton returned null debug info bytes.");
    }
    try {
      KryptonDebugInfo proto =
          KryptonDebugInfo.parseFrom(bytes, ExtensionRegistryLite.getEmptyRegistry());
      return KryptonDebugJson.fromProto(proto);
    } catch (InvalidProtocolBufferException e) {
      throw new KryptonException("Invalid debug info proto bytes from Krypton.", e);
    }
  }
}
