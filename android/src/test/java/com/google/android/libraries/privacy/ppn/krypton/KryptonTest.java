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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.robolectric.Shadows.shadowOf;

import android.os.ConditionVariable;
import android.os.Looper;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.testing.mockito.Mocks;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link Krypton}. */
@RunWith(RobolectricTestRunner.class)
public class KryptonTest {
  private static final String TAG = "KryptonTest";

  private static final String INVALID_URL = "http://unknown";

  @Rule public Mocks mocks = new Mocks(this);
  @Mock private KryptonListener kryptonListener;
  private final Executor backgroundExecutor = Executors.newSingleThreadExecutor();
  private final MockZinc mockZinc = new MockZinc();
  private final MockBrass mockBrass = new MockBrass();

  private static JSONObject buildAuthAndSignRequestBody() throws JSONException {
    JSONObject message = new JSONObject();
    message.put("oauth_token", "some_auth_token");
    message.put("service_type", "some_service_type");
    return message;
  }

  private static KryptonConfig createConfig(String zincUrl, String brassUrl) {
    return KryptonConfig.newBuilder()
        .setZincUrl(zincUrl)
        .setBrassUrl(brassUrl)
        .setServiceType("some_service_type")
        .setBridgeOverPpn(true)
        .setIpsecDatapath(false)
        .setEnableBlindSigning(false)
        .build();
  }

  private static KryptonConfig createConfigSafeDisconnect(
      String zincUrl, String brassUrl, boolean enable) {
    return KryptonConfig.newBuilder()
        .setZincUrl(zincUrl)
        .setBrassUrl(brassUrl)
        .setServiceType("some_service_type")
        .setBridgeOverPpn(true)
        .setIpsecDatapath(false)
        .setEnableBlindSigning(false)
        .setSafeDisconnectEnabled(enable)
        .build();
  }

  Krypton createKrypton() {
    HttpFetcher httpFetcher = new HttpFetcher(new TestBoundSocketFactoryFactory());
    return new KryptonImpl(httpFetcher, kryptonListener, backgroundExecutor);
  }

  @Test
  public void start_invalidZincUrl_terminatesSession() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable condition = new ConditionVariable(false);

    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    AtomicReference<PpnStatus> status = new AtomicReference<>();
    doAnswer(
            invocation -> {
              status.set(invocation.getArgument(0));
              condition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonDisconnected(any(PpnStatus.class));

    try {
      krypton.start(createConfig(INVALID_URL, INVALID_URL));
      assertThat(condition.block(1000)).isTrue();
      // Validate the Status
      assertThat(status.get().getCode()).isEqualTo(PpnStatus.Code.INTERNAL);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void start_permanentFailureFromZinc_permanentFailure() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable condition = new ConditionVariable(false);

    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    mockZinc.start();
    mockZinc.enqueueNegativeResponseWithCode(403, "Auth failed");

    AtomicReference<PpnStatus> status = new AtomicReference<>();
    doAnswer(
            invocation -> {
              status.set(invocation.getArgument(0));
              condition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonPermanentFailure(any(PpnStatus.class));

    try {
      krypton.start(createConfig(mockZinc.url(), INVALID_URL));
      assertThat(condition.block(1000)).isTrue();
      // Validate the Status
      assertThat(status.get().getCode()).isEqualTo(PpnStatus.Code.PERMISSION_DENIED);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void start_invalidBrassUrl_terminatesSession() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable condition = new ConditionVariable(false);

    mockZinc.start();
    mockZinc.enqueuePositiveResponse();

    mockBrass.start();
    mockBrass.enqueuePositiveResponse();

    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    AtomicReference<PpnStatus> status = new AtomicReference<>();
    doAnswer(
            invocation -> {
              status.set(invocation.getArgument(0));
              condition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonDisconnected(any(PpnStatus.class));

    try {
      krypton.start(createConfig(mockZinc.url(), INVALID_URL));
      assertThat(condition.block(1000)).isTrue();

      // Validate the Status
      assertThat(status.get().getCode()).isEqualTo(PpnStatus.Code.INTERNAL);
      // Validate the AuthAndSignRequest
      final RecordedRequest authAndSignRequest = mockZinc.takeRequest();
      final String authAndSignBody = authAndSignRequest.getBody().readUtf8();
      assertThat(authAndSignBody).isEqualTo(buildAuthAndSignRequestBody().toString());
      assertThat(authAndSignRequest.getHeader("Content-Type"))
          .isEqualTo("application/json; charset=utf-8");


    } finally {
      krypton.stop();
    }
  }

  @Test
  public void start_establishesSession() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable condition = new ConditionVariable(false);

    mockZinc.start();
    mockZinc.enqueuePositiveResponse();

    mockBrass.start();
    mockBrass.enqueuePositiveResponse();

    doReturn(0xbeef).when(kryptonListener).onKryptonNeedsTunFd(any(TunFdData.class));
    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    doAnswer(
            invocation -> {
              condition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonControlPlaneConnected();

    try {
      krypton.start(createConfig(mockZinc.url(), mockBrass.url()));
      assertThat(condition.block(1000)).isTrue();

      // Validate the AuthAndSignRequest
      final RecordedRequest addAndSignRequest = mockZinc.takeRequest();
      final String addAndSignRequestBody = addAndSignRequest.getBody().readUtf8();
      assertThat(addAndSignRequestBody).isEqualTo(buildAuthAndSignRequestBody().toString());
      assertThat(addAndSignRequest.getHeader("Content-Type"))
          .isEqualTo("application/json; charset=utf-8");

      // Validate the AddEgressRequest
      final RecordedRequest addEgressRequest = mockBrass.takeRequest();
      assertThat(addEgressRequest.getHeader("Content-Type"))
          .isEqualTo("application/json; charset=utf-8");

      // Test Pause that it is reaching native code.
      KryptonException expected = assertThrows(KryptonException.class, () -> krypton.pause(0));
      assertThat(expected).hasMessageThat().isEqualTo("UNIMPLEMENTED: Implement this");

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void start_brassFailure_reconnectSuccessful() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable connectedCondition = new ConditionVariable(false);
    final ConditionVariable restartCondition = new ConditionVariable(false);
    mockZinc.start();
    mockZinc.enqueuePositiveResponse();
    mockZinc.enqueuePositiveResponse();

    mockBrass.start();
    // Send 402 for AddEgressResponse.
    mockBrass.enqueueNegativeResponseWithCode(402, "Something went wrong with the server");
    mockBrass.enqueuePositiveResponse();

    doReturn(0xbeef).when(kryptonListener).onKryptonNeedsTunFd(any(TunFdData.class));
    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    doAnswer(
            invocation -> {
              restartCondition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonDisconnected(any(PpnStatus.class));

    doAnswer(
            invocation -> {
              connectedCondition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonControlPlaneConnected();

    try {
      krypton.start(createConfig(mockZinc.url(), mockBrass.url()));

      assertThat(restartCondition.block(2000)).isTrue();

      // Let the Looper run everything till the first reconnect timer of 2 secs expires.
      shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(2));

      assertThat(connectedCondition.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void start_passesSafeDisconnect() throws Exception {
    Krypton krypton = createKrypton();
    final ConditionVariable condition = new ConditionVariable(false);

    mockZinc.start();
    mockZinc.enqueuePositiveResponse();
    mockBrass.start();
    mockBrass.enqueuePositiveResponse();
    doReturn(0xbeef).when(kryptonListener).onKryptonNeedsTunFd(any(TunFdData.class));
    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    doAnswer(
            invocation -> {
              condition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonControlPlaneConnected();

    try {
      krypton.start(createConfigSafeDisconnect(mockZinc.url(), mockBrass.url(), true));
      assertThat(condition.block(1000)).isTrue();

      // Validate the Safe Disconnect config value.
      assertThat(krypton.isSafeDisconnectEnabled()).isTrue();

      // Update Safe Disconnect while Krypton is alive.
      krypton.setSafeDisconnectEnabled(false);
      assertThat(krypton.isSafeDisconnectEnabled()).isFalse();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void debugInfo_isPopulated() throws Exception {
    Krypton krypton = createKrypton();
    mockZinc.start();
    mockZinc.enqueuePositiveResponse();
    mockBrass.start();
    mockBrass.enqueuePositiveResponse();
    doReturn(0xbeef).when(kryptonListener).onKryptonNeedsTunFd(any(TunFdData.class));
    doReturn("some_auth_token").when(kryptonListener).onKryptonNeedsOAuthToken();

    final ConditionVariable connectedCondition = new ConditionVariable(false);
    doAnswer(
            invocation -> {
              connectedCondition.open();
              return null;
            })
        .when(kryptonListener)
        .onKryptonControlPlaneConnected();

    try {
      krypton.start(createConfig(mockZinc.url(), mockBrass.url()));
      assertThat(connectedCondition.block(1000)).isTrue();

      JSONObject debugInfo = krypton.getDebugJson();

      assertThat(debugInfo.opt(KryptonDebugJson.AUTH_STATE)).isEqualTo("Authenticated");
      assertThat(debugInfo.opt(KryptonDebugJson.AUTH_STATUS)).isEqualTo("OK");
      assertThat(debugInfo.opt(KryptonDebugJson.BRASS_URL)).isEqualTo(mockBrass.url());
      assertThat(debugInfo.optBoolean(KryptonDebugJson.CANCELLED)).isFalse();
      assertThat(debugInfo.opt(KryptonDebugJson.SUCCESSIVE_CONTROL_PLANE_FAILURES)).isEqualTo(1);
      assertThat(debugInfo.opt(KryptonDebugJson.EGRESS_STATE)).isEqualTo("kEgressSessionCreated");
      assertThat(debugInfo.opt(KryptonDebugJson.EGRESS_STATUS)).isEqualTo("OK");
      assertThat(debugInfo.opt(KryptonDebugJson.RECONNECTOR_STATE)).isEqualTo("Connected");
      assertThat(debugInfo.opt(KryptonDebugJson.SERVICE_TYPE)).isEqualTo("some_service_type");
      assertThat(debugInfo.opt(KryptonDebugJson.SESSION_RESTART_COUNTER)).isEqualTo(1);
      assertThat(debugInfo.opt(KryptonDebugJson.SESSION_STATE)).isEqualTo("kConnected");
      assertThat(debugInfo.opt(KryptonDebugJson.SESSION_STATUS)).isEqualTo("OK");
      assertThat(debugInfo.has(KryptonDebugJson.SESSION_ACTIVE_TUN_FD)).isFalse();
      assertThat(debugInfo.opt(KryptonDebugJson.ZINC_URL)).isEqualTo(mockZinc.url());
    } finally {
      krypton.stop();
    }
  }
}

/**
 * TODO: Add this additional test cases 1. A response whose content type is something
 * wrong, like "text/html". 2. A response whose body is valid json, but missing some required
 * fields.
 */
