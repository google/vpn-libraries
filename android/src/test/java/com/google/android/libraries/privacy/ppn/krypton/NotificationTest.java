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

import static com.google.common.truth.Truth.assertThat;

import android.os.ConditionVariable;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.google.android.libraries.privacy.ppn.PpnSnoozeStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus.Code;
import com.google.android.libraries.privacy.ppn.PpnStatus.DetailedErrorCode;
import com.google.android.libraries.privacy.ppn.internal.ConnectingStatus;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.DisconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.ReconnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.ResumeStatus;
import com.google.android.libraries.privacy.ppn.internal.SnoozeStatus;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.android.libraries.privacy.ppn.internal.http.BoundSocketFactoryFactory;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.protobuf.ByteString;
import com.google.protobuf.Duration;
import com.google.protobuf.Timestamp;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for JNI notifications from Krypton C++ to KryptonImpl.java. */
@RunWith(RobolectricTestRunner.class)
public class NotificationTest {
  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  @Mock private BoundSocketFactoryFactory socketFactoryFactory;

  private final JniTestNotification notification = new JniTestNotification();
  private final ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor();
  private final HttpFetcher httpFetcher = new HttpFetcher(socketFactoryFactory);

  private static final String IPSEC_4_BYTE_SAMPLE = "abcd";
  private static final String IPSEC_32_BYTE_SAMPLE = "0123456789abcdef0123456789abcdef";

  @Before
  public void setUp() {
    WorkManagerTestInitHelper.initializeTestWorkManager(
        ApplicationProvider.getApplicationContext());
  }

  private KryptonImpl createKrypton(KryptonListener listener) {
    OAuthTokenProvider tokenProvider =
        new OAuthTokenProvider() {
          @Override
          public String getOAuthToken() {
            return "some_oauth_token";
          }

          @Override
          public byte[] getAttestationData(String nonce) {
            return null;
          }

          @Override
          public void clearOAuthToken(String token) {}
        };
    return new KryptonImpl(
        ApplicationProvider.getApplicationContext(),
        httpFetcher,
        tokenProvider,
        listener,
        backgroundExecutor);
  }

  @Test
  public void connected_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<ConnectionStatus> statusRef = new AtomicReference<>();
    ConditionVariable connected = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonConnected(ConnectionStatus status) {
                statusRef.set(status);
                connected.open();
              }
            });

    try {
      krypton.init();

      ConnectionStatus status =
          ConnectionStatus.newBuilder().setQuality(ConnectionStatus.ConnectionQuality.GOOD).build();
      notification.connected(krypton, status);

      assertThat(connected.block(1000)).isTrue();
      assertThat(statusRef.get().getQuality()).isEqualTo(ConnectionStatus.ConnectionQuality.GOOD);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void connecting_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<ConnectingStatus> statusRef = new AtomicReference<>();
    ConditionVariable connecting = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonConnecting(ConnectingStatus status) {
                statusRef.set(status);
                connecting.open();
              }
            });

    try {
      krypton.init();

      ConnectingStatus status = ConnectingStatus.newBuilder().setIsBlockingTraffic(true).build();
      notification.connecting(krypton, status);

      assertThat(connecting.block(1000)).isTrue();
      assertThat(statusRef.get().getIsBlockingTraffic()).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void controlPlaneConnected_callsCallback() throws Exception {
    // Set up a condition we can wait on.
    ConditionVariable connected = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonControlPlaneConnected() {
                connected.open();
              }
            });

    try {
      krypton.init();

      notification.controlPlaneConnected(krypton);

      assertThat(connected.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void statusUpdated_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<ConnectionStatus> statusRef = new AtomicReference<>();
    ConditionVariable statusUpdated = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonStatusUpdated(ConnectionStatus status) {
                statusRef.set(status);
                statusUpdated.open();
              }
            });

    try {
      krypton.init();

      ConnectionStatus status =
          ConnectionStatus.newBuilder().setQuality(ConnectionStatus.ConnectionQuality.GOOD).build();
      notification.statusUpdate(krypton, status);

      assertThat(statusUpdated.block(1000)).isTrue();
      assertThat(statusRef.get().getQuality()).isEqualTo(ConnectionStatus.ConnectionQuality.GOOD);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void disconnected_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<DisconnectionStatus> statusRef = new AtomicReference<>();
    ConditionVariable disconnected = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonDisconnected(DisconnectionStatus status) {
                statusRef.set(status);
                disconnected.open();
              }
            });

    try {
      krypton.init();

      DisconnectionStatus status =
          DisconnectionStatus.newBuilder()
              .setCode(Code.PERMISSION_DENIED.getCode())
              .setMessage("This is a test.")
              .setIsBlockingTraffic(true)
              .build();
      notification.disconnected(krypton, status);

      assertThat(disconnected.block(1000)).isTrue();
      assertThat(statusRef.get().getCode()).isEqualTo(Code.PERMISSION_DENIED.getCode());
      assertThat(statusRef.get().getMessage()).isEqualTo("This is a test.");
      assertThat(statusRef.get().getIsBlockingTraffic()).isTrue();

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void permanentFailure_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<PpnStatus> statusRef = new AtomicReference<>();
    ConditionVariable failed = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonPermanentFailure(PpnStatus status) {
                statusRef.set(status);
                failed.open();
              }
            });

    try {
      krypton.init();

      PpnStatus status =
          new PpnStatus.Builder(Code.RESOURCE_EXHAUSTED, "Another test.")
              .setDetailedErrorCode(DetailedErrorCode.DISALLOWED_COUNTRY)
              .build();
      notification.permanentFailure(krypton, status);

      assertThat(failed.block(1000)).isTrue();
      assertThat(statusRef.get().getCode()).isEqualTo(Code.RESOURCE_EXHAUSTED);
      assertThat(statusRef.get().getMessage()).isEqualTo("Another test.");
      assertThat(statusRef.get().getDetailedErrorCode())
          .isEqualTo(DetailedErrorCode.DISALLOWED_COUNTRY);

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void waitingToReconnect_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<ReconnectionStatus> statusRef = new AtomicReference<>();
    ConditionVariable waitingToReconnect = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonWaitingToReconnect(ReconnectionStatus status) {
                statusRef.set(status);
                waitingToReconnect.open();
              }
            });

    try {
      krypton.init();

      ReconnectionStatus reconnectionStatus =
          ReconnectionStatus.newBuilder()
              .setTimeToReconnect(Duration.newBuilder().setSeconds(5).build())
              .build();
      notification.waitingToReconnect(krypton, reconnectionStatus);

      assertThat(waitingToReconnect.block(1000)).isTrue();
      assertThat(statusRef.get().getTimeToReconnect().getSeconds()).isEqualTo(5);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void networkDisconnected_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<NetworkInfo> networkRef = new AtomicReference<>();
    AtomicReference<PpnStatus> statusRef = new AtomicReference<>();
    ConditionVariable networkDisconnected = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonNetworkFailed(PpnStatus status, NetworkInfo network) {
                networkRef.set(network);
                statusRef.set(status);
                networkDisconnected.open();
              }
            });

    try {
      krypton.init();

      NetworkInfo network = NetworkInfo.newBuilder().setNetworkId(42).build();
      PpnStatus status =
          new PpnStatus.Builder(Code.DATA_LOSS, "More tests.")
              .setDetailedErrorCode(DetailedErrorCode.DISALLOWED_COUNTRY)
              .build();
      notification.networkDisconnected(krypton, network, status);

      assertThat(networkDisconnected.block(1000)).isTrue();
      assertThat(networkRef.get().getNetworkId()).isEqualTo(42);
      assertThat(statusRef.get().getCode()).isEqualTo(Code.DATA_LOSS);
      assertThat(statusRef.get().getMessage()).isEqualTo("More tests.");
      assertThat(statusRef.get().getDetailedErrorCode())
          .isEqualTo(DetailedErrorCode.DISALLOWED_COUNTRY);

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void snoozePpn_callsCallback() throws Exception {
    long snoozeDuration = 300L;
    AtomicReference<PpnSnoozeStatus> snoozeStatusRef = new AtomicReference<>();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonSnoozed(SnoozeStatus status) {
                snoozeStatusRef.set(PpnSnoozeStatus.fromProto(status));
              }
            });
    try {
      krypton.init();

      SnoozeStatus snoozeStatus =
          SnoozeStatus.newBuilder()
              .setSnoozeEndTime(
                  Timestamp.newBuilder().setSeconds(snoozeDuration).setNanos(0).build())
              .build();
      notification.snoozed(krypton, snoozeStatus);
      assertThat(snoozeStatusRef.get().getSnoozeEndTime())
          .isEqualTo(Instant.ofEpochSecond(snoozeDuration));
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void resumePpn_callsCallback() throws Exception {
    ConditionVariable resume = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonResumed(ResumeStatus status) {
                resume.open();
              }
            });
    try {
      krypton.init();

      ResumeStatus resumeStatus = ResumeStatus.getDefaultInstance();
      notification.resumed(krypton, resumeStatus);
      assertThat(resume.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void createTunFd_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<TunFdData> tunFdDataRef = new AtomicReference<>();
    int testFd = notification.createSockFdTestOnly();
    assertThat(testFd).isGreaterThan(0);
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public int onKryptonNeedsTunFd(TunFdData tunFdData) {
                tunFdDataRef.set(tunFdData);
                return testFd;
              }
            });

    try {
      krypton.init();

      TunFdData tunFdData = TunFdData.newBuilder().setMtu(12345).build();
      int fd = notification.createTunFd(krypton, tunFdData);

      assertThat(fd).isEqualTo(testFd);
      assertThat(tunFdDataRef.get().getMtu()).isEqualTo(12345);
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void createNetworkFd_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<NetworkInfo> networkRef = new AtomicReference<>();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public int onKryptonNeedsNetworkFd(NetworkInfo network) {
                networkRef.set(network);
                return 123;
              }
            });

    try {
      krypton.init();

      NetworkInfo network = NetworkInfo.newBuilder().setNetworkId(321).build();
      int fd = notification.createNetworkFd(krypton, network);

      assertThat(fd).isEqualTo(123);
      assertThat(networkRef.get().getNetworkId()).isEqualTo(321);

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void createTcpFd_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<NetworkInfo> networkRef = new AtomicReference<>();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public int onKryptonNeedsTcpFd(NetworkInfo network) {
                networkRef.set(network);
                return 456;
              }
            });

    try {
      krypton.init();

      NetworkInfo network = NetworkInfo.newBuilder().setNetworkId(654).build();
      int fd = notification.createTcpFd(krypton, network);

      assertThat(fd).isEqualTo(456);
      assertThat(networkRef.get().getNetworkId()).isEqualTo(654);

    } finally {
      krypton.stop();
    }
  }

  /**
   * We are only able to verify if the proper arguments have been passed to KryptonIpSecHelper and
   * we are not able to verify if the transform are actually applied.
   *
   * <p>This limitation stems from not being able to obtain an instance of IpSecManager from the
   * Test Runner.
   */
  @Test
  public void connectedFd_applyTransformOk() throws Exception {
    ConditionVariable condition = new ConditionVariable();
    KryptonImpl krypton =
        createKrypton(
            new KryptonAdapter() {
              @Override
              public void onKryptonNeedsIpSecConfiguration(IpSecTransformParams params) {
                condition.open();
              }
            });
    try {
      krypton.init();
      IpSecTransformParams params =
          IpSecTransformParams.newBuilder()
              .setUplinkKey(ByteString.copyFrom(IPSEC_32_BYTE_SAMPLE, Charset.defaultCharset()))
              .setUplinkSalt(ByteString.copyFrom(IPSEC_4_BYTE_SAMPLE, Charset.defaultCharset()))
              .setDownlinkKey(ByteString.copyFrom(IPSEC_32_BYTE_SAMPLE, Charset.defaultCharset()))
              .setDownlinkSalt(ByteString.copyFrom(IPSEC_4_BYTE_SAMPLE, Charset.defaultCharset()))
              .setNetworkFd(1)
              .setUplinkSpi(1)
              .setDownlinkSpi(2)
              .build();
      assertThat(notification.configureIpSec(krypton, params)).isTrue();
    } finally {
      krypton.stop();
    }
  }
}
