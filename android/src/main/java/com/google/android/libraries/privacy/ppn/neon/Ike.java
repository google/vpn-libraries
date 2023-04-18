/*
 * Copyright (C) 2021 Google Inc.
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

import android.content.Context;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.AttestationHelper;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider;
import com.google.android.libraries.privacy.ppn.proto.PpnIkeResponse;

/** Class for standalone API methods for using IKE with PPN. */
public class Ike {
  /**
   * Attempts to provision IKE credentials for PPN one time.
   *
   * <p>If provisioning fails, returned Task will be failed. If the Exception is of type
   * ProvisionException, then it can be checked for whether the error is permanent or transient. If
   * any other type of Exception occurs, it should be considered permanent.
   */
  public static Task<ProvisionResponse> provision(
      Context context, PpnOptions options, String oauthToken) {
    HttpFetcher httpFetcher = new HttpFetcher(new ProvisionSocketFactoryFactory());

    final OAuthTokenProvider tokenProvider;
    if (options.isHardwareAttestationEnabled()) {
      final AttestationHelper attestationHelper = new AttestationHelper(context, options);
      tokenProvider =
          new OAuthTokenProvider() {
            @Override
            public String getOAuthToken() {
              return oauthToken;
            }

            @Override
            @Nullable
            public byte[] getAttestationData(String nonce) {
              return attestationHelper.getAttestationData(nonce);
            }
          };
    } else {
      tokenProvider =
          new OAuthTokenProvider() {
            @Override
            public String getOAuthToken() {
              return oauthToken;
            }

            @Override
            @Nullable
            public byte[] getAttestationData(String nonce) {
              return null;
            }
          };
    }

    TaskCompletionSource<ProvisionResponse> tcs = new TaskCompletionSource<>();
    Provision.Listener internalListener =
        new Provision.Listener() {
          @Override
          public void onProvisioned(PpnIkeResponse responseProto) {
            try {
              ProvisionResponse response = ProvisionResponse.createFromIkeResponse(responseProto);
              tcs.trySetResult(response);
            } catch (ProvisionException e) {
              tcs.trySetException(e);
            }
          }

          @Override
          public void onProvisioningFailure(PpnStatus status, boolean permanent) {
            tcs.trySetException(new ProvisionException(status, permanent));
          }
        };

    try {
      Provision p = new Provision(options, httpFetcher, tokenProvider, internalListener);
      p.start();
    } catch (PpnException e) {
      tcs.trySetException(e);
    }

    return tcs.getTask();
  }

  private Ike() {}
}
