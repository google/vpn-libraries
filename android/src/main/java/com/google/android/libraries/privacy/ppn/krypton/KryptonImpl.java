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

import android.content.Context;
import android.util.Log;
import androidx.annotation.VisibleForTesting;
import androidx.work.WorkManager;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectingStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import com.google.android.libraries.privacy.ppn.internal.KryptonDebugInfo;
import com.google.android.libraries.privacy.ppn.internal.KryptonTelemetry;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.PpnStatusDetails;
import com.google.android.libraries.privacy.ppn.internal.ReconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ResumeStatus;
import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.concurrent.ExecutorService;
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

  // In order to use JNI, somebody has to call System.loadLibrary.
  // We can't call it from multiple places, so this block is the one true place to load it.
  // Therefore, any class that needs JNI just needs to make sure the static block is called.
  // Normally, this isn't an issue, since any binary that uses Krypton will already have it loaded.
  static {
    Log.i(TAG, "Loading krypton_jni library.");
    System.loadLibrary("krypton_jni");
  }
  // Helper for binaries that use Krypton JNI methods without creating an actual Krypton instance.
  // It can be a no-op, because all that needs to happen is for the static block above to run.
  public static void ensureJniIsLoaded() {}

  private final KryptonListener listener;
  private final HttpFetcher httpFetcher;
  private final ExecutorService backgroundExecutor;
  private final TimerIdManager timerIdManager;
  private final OAuthTokenProvider oAuthTokenProvider;

  /**
   * Initializes a Krypton instance with the given parameters.
   *
   * @param kryptonListener The listener to callback with events from Krypton.
   * @param backgroundExecutor An executor to use for any background work Krypton needs to do.
   */
  public KryptonImpl(
      Context context,
      HttpFetcher httpFetcher,
      OAuthTokenProvider oAuthTokenProvider,
      KryptonListener kryptonListener,
      ExecutorService backgroundExecutor) {
    this.httpFetcher = httpFetcher;
    this.oAuthTokenProvider = oAuthTokenProvider;
    this.listener = kryptonListener;
    this.backgroundExecutor = backgroundExecutor;
    this.timerIdManager =
        new TimerIdManager(this, WorkManager.getInstance(context.getApplicationContext()));
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
   * Snoozes Krypton.
   *
   * <p>Implemented in the native library |Krypton::Snooze|
   */
  @Override
  public native void snooze(long snoozeDurationMs) throws KryptonException;

  /**
   * Extends Krypton snooze duration.
   *
   * <p>Implemented in native library |Krypton::ExtendSnooze|
   */
  @Override
  public native void extendSnooze(long extendSnoozeDurationMs) throws KryptonException;

  /**
   * Resumes Krypton.
   *
   * <p>Implemented in the native library |Krypton::Resume|
   */
  @Override
  public native void resume() throws KryptonException;

  /**
   * Stops the Krypton service, closing any open connections.
   *
   * <p>Implemented in the native library |Krypton::Stop|
   */
  private native void stopNative() throws KryptonException;

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

  /** Update the level of IP geo used by PPN. Will cause a reconnect. */
  @Override
  public void setIpGeoLevel(KryptonConfig.IpGeoLevel level) throws KryptonException {
    setIpGeoLevelNative(level.getNumber());
  }

  /** Gets the IP geo level currently in use. */
  @Override
  public KryptonConfig.IpGeoLevel getIpGeoLevel() throws KryptonException {
    return KryptonConfig.IpGeoLevel.forNumber(getIpGeoLevelNative());
  }

  private native void setIpGeoLevelNative(int level) throws KryptonException;

  private native int getIpGeoLevelNative() throws KryptonException;

  /** Native method for putting Krypton into a horrible wedged state. */
  @Override
  public native void setSimulatedNetworkFailure(boolean simulatedNetworkFailure)
      throws KryptonException;

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

  /** Native method for disabling the keepalive in native code. */
  private native void disableKryptonKeepaliveNative() throws KryptonException;

  // LINT.ThenChange(//depot/google3/privacy/net/krypton/jni/krypton_jni.cc)

  // Java methods, called using jni_cache.cc

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

  private void onConnecting(byte[] statusBytes) {
    try {
      ConnectingStatus status =
          ConnectingStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonConnecting(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
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

  private void onDisconnected(byte[] statusBytes) {
    try {
      DisconnectionStatus disconnectionStatus =
          DisconnectionStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonDisconnected(disconnectionStatus);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  /** Used for notifying the network that is being used has disconnected. */
  private void onNetworkFailed(
      byte[] networkInfoBytes, int code, String reason, byte[] detailsBytes) {
    try {
      NetworkInfo networkInfo =
          NetworkInfo.parseFrom(networkInfoBytes, ExtensionRegistryLite.getEmptyRegistry());
      PpnStatusDetails details =
          PpnStatusDetails.parseFrom(detailsBytes, ExtensionRegistryLite.getEmptyRegistry());
      PpnStatus status =
          new PpnStatus.Builder(code, reason)
              .setDetailedErrorCode(
                  PpnStatus.DetailedErrorCode.fromCode(details.getDetailedErrorCode().getNumber()))
              .build();

      listener.onKryptonNetworkFailed(status, networkInfo);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to create network info.", e);
    }
  }

  private void onPermanentFailure(int code, String reason, byte[] detailsBytes) {
    try {
      PpnStatusDetails details =
          PpnStatusDetails.parseFrom(detailsBytes, ExtensionRegistryLite.getEmptyRegistry());
      PpnStatus status =
          new PpnStatus.Builder(code, reason)
              .setDetailedErrorCode(
                  PpnStatus.DetailedErrorCode.fromCode(details.getDetailedErrorCode().getNumber()))
              .build();

      // Make sure to run this asynchronously, so that stopping Krypton won't cause deadlocks.
      backgroundExecutor.execute(() -> listener.onKryptonPermanentFailure(status));
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to parse status details.", e);
    }
  }

  private void onCrashed() {
    listener.onKryptonCrashed();
  }

  private void onWaitingToReconnect(byte[] statusBytes) {
    try {
      ReconnectionStatus status =
          ReconnectionStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonWaitingToReconnect(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  private void onKryptonSnoozed(byte[] statusBytes) {
    try {
      SnoozeStatus status =
          SnoozeStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonSnoozed(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  private void onKryptonResumed(byte[] statusBytes) {
    try {
      ResumeStatus status =
          ResumeStatus.parseFrom(statusBytes, ExtensionRegistryLite.getEmptyRegistry());
      listener.onKryptonResumed(status);
    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
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
   * Used to call into the PPN service and create a new network fd that uses TCP/IP. Krypton takes
   * ownership of the returned fd, and is responsible for closing it. This is used specifically for
   * determining MTU.
   *
   * @return the file descriptor, or a negative value, if one could not be created.
   */
  private int createTcpFd(byte[] networkInfoBytes) {
    try {
      NetworkInfo networkInfo =
          NetworkInfo.parseFrom(networkInfoBytes, ExtensionRegistryLite.getEmptyRegistry());
      return listener.onKryptonNeedsTcpFd(networkInfo);
    } catch (PpnException | InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to create TCP/IP fd.", e);
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
      Log.e(TAG, "Configuring IpSec was successful.");
      return true;
    } catch (Exception e) {
      Log.e(TAG, "Unable to configure IpSec.", e);
      return false;
    }
  }

  /** Used to call into the PPN service to get a new OAuth token for Zinc. */
  private OAuthTokenProvider getOAuthTokenProvider() {
    return oAuthTokenProvider;
  }

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
   * Stops the Krypton service, closing any open connections.
   *
   * <p>Implemented in the native library |Krypton::Stop|
   */
  @Override
  public void stop() throws KryptonException {
    stopNative();
    timerIdManager.stop();
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

  @Override
  public void disableKryptonKeepalive() throws KryptonException {
    disableKryptonKeepaliveNative();
  }
}
