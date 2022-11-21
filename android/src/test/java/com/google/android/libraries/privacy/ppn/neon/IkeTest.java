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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.robolectric.Shadows.shadowOf;

import android.os.Looper;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnOptions.DatapathProtocol;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.krypton.MockBrass;
import com.google.android.libraries.privacy.ppn.krypton.MockZinc;
import com.google.errorprone.annotations.ResultIgnorabilityUnspecified;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class IkeTest {
  private final MockZinc mockZinc = new MockZinc();
  private final MockBrass mockBrass = new MockBrass();

  private PpnOptions createOptions() {
    return new PpnOptions.Builder()
        .setZincUrl(mockZinc.url())
        .setZincPublicSigningKeyUrl(mockZinc.url())
        .setBrassUrl(mockBrass.url())
        .setZincServiceType("some_service_type")
        .setDatapathProtocol(DatapathProtocol.IKE)
        .setBlindSigningEnabled(true)
        .build();
  }

  @Test
  public void provision_successful() throws Exception {
    mockZinc.start();
    mockZinc.enqueuePositivePublicKeyResponse();
    mockZinc.enqueuePositiveAuthResponse();

    mockBrass.start();
    mockBrass.enqueuePositiveIkeResponse();

    Task<ProvisionResponse> task =
        Ike.provision(ApplicationProvider.getApplicationContext(), createOptions(), "some token");

    await(task);

    ProvisionResponse response = task.getResult();
    assertThat(response.getServerAddress()).isEqualTo("server");
    assertThat(response.getClientId()).isEqualTo("client".getBytes(UTF_8));
    assertThat(response.getSharedSecret()).isEqualTo("secret".getBytes(UTF_8));
  }

  @Test
  public void start_failedProvision() throws Exception {
    mockZinc.start();
    mockZinc.enqueuePositivePublicKeyResponse();
    mockZinc.enqueuePositiveAuthResponse();

    mockBrass.start();
    mockBrass.enqueueNegativeResponseWithCode(500, "unavailable");

    Task<Void> task =
        Ike.provision(ApplicationProvider.getApplicationContext(), createOptions(), "some token")
            .continueWithTask(
                provisionTask -> {
                  if (provisionTask.isSuccessful()) {
                    throw new RuntimeException("expected failure");
                  }

                  Exception exception = provisionTask.getException();
                  assertThat(exception).isInstanceOf(ProvisionException.class);

                  ProvisionException e = (ProvisionException) exception;
                  assertThat(e.isPermanent()).isFalse();
                  assertThat(e.getStatus().getCode()).isEqualTo(PpnStatus.Code.INTERNAL);

                  return Tasks.forResult((Void) null);
                });

    await(task);
  }

  /**
   * Blocks until the given task is complete. This can't use Tasks.await, because the async work may
   * need to run on the main thread.
   */
  @ResultIgnorabilityUnspecified
  private static <T> T await(Task<T> task) {
    while (!task.isComplete()) {
      // Allow the main looper to clear itself out.
      shadowOf(Looper.getMainLooper()).idle();
    }
    return task.getResult();
  }
}
