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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.robolectric.Shadows.shadowOf;

import android.net.Network;
import android.os.Looper;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnOptions.DatapathProtocol;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.krypton.FakeAuthServer;
import com.google.android.libraries.privacy.ppn.krypton.MockBrass;
import com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider;
import com.google.android.libraries.privacy.ppn.proto.PpnIkeResponse;
import java.net.Socket;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class ProvisionTest {
  private final FakeAuthServer fakeAuthServer = new FakeAuthServer();
  private final MockBrass mockBrass = new MockBrass();

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();
  @Mock private Network mockNetwork;

  private PpnOptions createOptions() {
    return new PpnOptions.Builder()
        .setZincUrl(fakeAuthServer.authUrl())
        .setZincPublicSigningKeyUrl(fakeAuthServer.publicKeyUrl())
        .setBrassUrl(mockBrass.url())
        .setZincServiceType("some_service_type")
        .setDatapathProtocol(DatapathProtocol.IKE)
        .setBlindSigningEnabled(true)
        .build();
  }

  private HttpFetcher createHttpFetcher(@Nullable Network network) {
    return new HttpFetcher(new ProvisionSocketFactoryFactory(network));
  }

  private OAuthTokenProvider createTokenProvider() {
    return new OAuthTokenProvider() {
      @Override
      public String getOAuthToken() {
        return "some token";
      }

      @Override
      public byte[] getAttestationData(String nonce) {
        return null;
      }

      @Override
      public void clearOAuthToken(String token) {}
    };
  }

  @Test
  public void start_successfulProvision() throws Exception {
    fakeAuthServer.start();
    fakeAuthServer.enqueuePositivePublicKeyResponse();
    fakeAuthServer.enqueuePositiveAuthResponse();

    mockBrass.start();
    mockBrass.enqueuePositiveIkeResponse();

    TaskCompletionSource<Void> tcs = new TaskCompletionSource<>();

    Provision provision =
        new Provision(
            createOptions(),
            createHttpFetcher(null),
            createTokenProvider(),
            new Provision.Listener() {
              @Override
              public void onProvisioned(PpnIkeResponse response) {
                tcs.trySetResult(null);
              }

              @Override
              public void onProvisioningFailure(PpnStatus status, boolean permanent) {
                tcs.trySetException(new RuntimeException("failed"));
              }
            });

    provision.start();

    await(tcs.getTask());
  }

  @Test
  public void start_failedProvision() throws Exception {
    fakeAuthServer.start();
    fakeAuthServer.enqueuePositivePublicKeyResponse();
    fakeAuthServer.enqueuePositiveAuthResponse();

    mockBrass.start();
    mockBrass.enqueueNegativeResponseWithCode(500, "unavailable");

    TaskCompletionSource<Void> tcs = new TaskCompletionSource<>();

    Provision provision =
        new Provision(
            createOptions(),
            createHttpFetcher(null),
            createTokenProvider(),
            new Provision.Listener() {
              @Override
              public void onProvisioned(PpnIkeResponse response) {
                tcs.trySetException(new RuntimeException("failed"));
              }

              @Override
              public void onProvisioningFailure(PpnStatus status, boolean permanent) {
                try {
                  assertThat(permanent).isFalse();
                  assertThat(status.getCode()).isEqualTo(PpnStatus.Code.INTERNAL);

                  tcs.trySetResult(null);
                } catch (RuntimeException e) {
                  tcs.trySetException(e);
                }
              }
            });

    provision.start();

    await(tcs.getTask());
  }

  @Test
  public void start_successfulProvisionWithNetworkOverride() throws Exception {
    fakeAuthServer.start();
    fakeAuthServer.enqueuePositivePublicKeyResponse();
    fakeAuthServer.enqueuePositiveAuthResponse();

    mockBrass.start();
    mockBrass.enqueuePositiveIkeResponse();

    TaskCompletionSource<Void> tcs = new TaskCompletionSource<>();

    Provision provision =
        new Provision(
            createOptions(),
            createHttpFetcher(mockNetwork),
            createTokenProvider(),
            new Provision.Listener() {
              @Override
              public void onProvisioned(PpnIkeResponse response) {
                tcs.trySetResult(null);
              }

              @Override
              public void onProvisioningFailure(PpnStatus status, boolean permanent) {
                tcs.trySetException(new RuntimeException("failed"));
              }
            });

    provision.start();

    await(tcs.getTask());

    // It should have used the network for 2 phosphor/zinc calls and 1 brass/beryllium call.
    verify(mockNetwork, times(3)).bindSocket(any(Socket.class));
    verifyNoMoreInteractions(mockNetwork);
  }

  /**
   * Blocks until the given task is complete. This can't use Tasks.await, because the async work may
   * need to run on the main thread.
   */
  private static <T> T await(Task<T> task) {
    while (!task.isComplete()) {
      // Allow the main looper to clear itself out.
      shadowOf(Looper.getMainLooper()).idle();
    }
    return task.getResult();
  }
}
