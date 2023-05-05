// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.neon;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import com.google.android.libraries.privacy.ppn.internal.PpnStatusDetails;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.krypton.KryptonException;
import com.google.android.libraries.privacy.ppn.krypton.KryptonImpl;
import com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider;
import com.google.android.libraries.privacy.ppn.proto.PpnIkeResponse;
import com.google.errorprone.annotations.ResultIgnorabilityUnspecified;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * Provision manages the sequence to do IKE provisioning. This class can be used as an alternative
 * to Krypton. It should not be used in the same PPN implementation that uses Krypton.
 */
class Provision {
  private static final String TAG = "Provision";

  static {
    KryptonImpl.ensureJniIsLoaded();
  }

  /** Listener for when provisioning finishes. */
  public interface Listener {

    /** Called when IKE provisioning completes successfully. */
    void onProvisioned(PpnIkeResponse response);

    /** Called when provisioning fails. */
    void onProvisioningFailure(PpnStatus status, boolean permanent);
  }

  private final KryptonConfig config;
  private final HttpFetcher httpFetcher;
  private final OAuthTokenProvider tokenProvider;
  private final Listener listener;

  private final Handler mainHandler = new Handler(Looper.getMainLooper());

  Provision(
      PpnOptions options,
      HttpFetcher httpFetcher,
      OAuthTokenProvider tokenProvider,
      Listener listener) {
    this.config = createKryptonConfig(options);
    this.httpFetcher = httpFetcher;
    this.tokenProvider = tokenProvider;
    this.listener = listener;
  }

  /**
   * Starts the provisioning flow. This can be called multiple times, but should only be called once
   * at a time for a single Provision instance.
   */
  public void start() throws PpnException {
    try {
      startNative(config.toByteArray(), httpFetcher, tokenProvider);
    } catch (KryptonException e) {
      throw new PpnException("Unable to start provisioning.", e);
    }
  }

  /**
   * Cleans up C++ state associated with provisioning. This should be called after the listener has
   * indicated that provisioning is finished.
   */
  private void stop(long nativeContext) {
    try {
      stopNative(nativeContext);
    } catch (KryptonException e) {
      // There's nowhere to return this cleanup failure, so just log it.
      Log.e(TAG, "Unable to stop provisioning.", e);
    }
  }

  /**
   * Native implementation of start().
   *
   * @param configBytes a serialized KryptonConfig proto.
   * @return a reference to the C++ object.
   */
  @ResultIgnorabilityUnspecified
  private native long startNative(
      byte[] configBytes, HttpFetcher httpFetcher, OAuthTokenProvider tokenProvider)
      throws KryptonException;

  /**
   * Native implementation of stop().
   *
   * @param nativeContext the reference to the C++ peer object.
   */
  private native void stopNative(long nativeContext) throws KryptonException;

  /** Called by C++ code when provisioning is complete. */
  private void onProvisioned(long nativeContext, byte[] ppnIkeResponseBytes) {
    try {
      Log.i(TAG, "Provisioning succeeded.");

      PpnIkeResponse response =
          PpnIkeResponse.parseFrom(ppnIkeResponseBytes, ExtensionRegistryLite.getEmptyRegistry());

      mainHandler.post(() -> listener.onProvisioned(response));
      mainHandler.post(() -> stop(nativeContext));

    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to decode PpnIkeResponse.", e);
    }
  }

  /** Called by C++ code when provisioning fails. */
  private void onProvisioningFailure(
      long nativeContext, int code, String reason, byte[] detailsBytes, boolean permanent) {
    try {
      Log.e(TAG, "Provisioning failed: " + code + ": " + reason);

      PpnStatusDetails details =
          PpnStatusDetails.parseFrom(detailsBytes, ExtensionRegistryLite.getEmptyRegistry());
      PpnStatus status =
          new PpnStatus.Builder(code, reason)
              .setDetailedErrorCode(
                  PpnStatus.DetailedErrorCode.fromCode(details.getDetailedErrorCode().getNumber()))
              .build();

      mainHandler.post(() -> listener.onProvisioningFailure(status, permanent));
      mainHandler.post(() -> stop(nativeContext));

    } catch (InvalidProtocolBufferException e) {
      Log.e(TAG, "Unable to decode provisioning failure.", e);
    }
  }

  static KryptonConfig createKryptonConfig(PpnOptions options) {
    return options.createKryptonConfigBuilder().build();
  }
}
