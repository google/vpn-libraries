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

import android.os.ConditionVariable;
import com.google.android.libraries.privacy.ppn.PpnReconnectStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus.Code;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.protobuf.ByteString;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for JNI notifications from Krypton C++ to KryptonImpl.java. */
@RunWith(RobolectricTestRunner.class)
public class NotificationTest {

  private final JniTestNotification notification = new JniTestNotification();
  private final HttpFetcher httpFetcher = new HttpFetcher(new TestBoundSocketFactoryFactory());
  private final Executor backgroundExecutor = Executors.newSingleThreadExecutor();

  private static final String IPSEC_4_BYTE_SAMPLE = "abcd";
  private static final String IPSEC_32_BYTE_SAMPLE = "0123456789abcdef0123456789abcdef";

  @Test
  public void connected_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<ConnectionStatus> statusRef = new AtomicReference<>();
    ConditionVariable connected = new ConditionVariable();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonConnected(ConnectionStatus status) {
                statusRef.set(status);
                connected.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.connected();

      assertThat(connected.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void connecting_callsCallback() throws Exception {
    // Set up a condition we can wait on.
    ConditionVariable connected = new ConditionVariable();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonConnecting() {
                connected.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.connecting();

      assertThat(connected.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void controlPlaneConnected_callsCallback() throws Exception {
    // Set up a condition we can wait on.
    ConditionVariable connected = new ConditionVariable();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonControlPlaneConnected() {
                connected.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.controlPlaneConnected();

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
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonStatusUpdated(ConnectionStatus status) {
                statusRef.set(status);
                statusUpdated.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.statusUpdated();

      assertThat(statusUpdated.block(1000)).isTrue();
    } finally {
      krypton.stop();
    }
  }

  @Test
  public void disconnected_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<PpnStatus> statusRef = new AtomicReference<>();
    ConditionVariable disconnected = new ConditionVariable();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonDisconnected(PpnStatus status) {
                statusRef.set(status);
                disconnected.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.disconnected(new PpnStatus(Code.PERMISSION_DENIED, "This is a test."));

      assertThat(disconnected.block(1000)).isTrue();
      assertThat(statusRef.get().getCode()).isEqualTo(Code.PERMISSION_DENIED);
      assertThat(statusRef.get().getMessage()).isEqualTo("This is a test.");

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
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonPermanentFailure(PpnStatus status) {
                statusRef.set(status);
                failed.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.permanentFailure(new PpnStatus(Code.RESOURCE_EXHAUSTED, "Another test."));

      assertThat(failed.block(1000)).isTrue();
      assertThat(statusRef.get().getCode()).isEqualTo(Code.RESOURCE_EXHAUSTED);
      assertThat(statusRef.get().getMessage()).isEqualTo("Another test.");

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void waitingToReconnect_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<PpnReconnectStatus> statusRef = new AtomicReference<>();
    ConditionVariable waitingToReconnect = new ConditionVariable();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonWaitingToReconnect(PpnReconnectStatus status) {
                statusRef.set(status);
                waitingToReconnect.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      notification.waitingToReconnect(new PpnReconnectStatus(Duration.ofSeconds(5)));

      assertThat(waitingToReconnect.block(1000)).isTrue();
      assertThat(statusRef.get().getTimeToReconnect()).isEqualTo(Duration.ofSeconds(5));
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
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonNetworkFailed(PpnStatus status, NetworkInfo network) {
                networkRef.set(network);
                statusRef.set(status);
                networkDisconnected.open();
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      NetworkInfo network = NetworkInfo.newBuilder().setNetworkId(42).build();
      PpnStatus status = new PpnStatus(Code.DATA_LOSS, "More tests.");
      notification.networkDisconnected(network, status);

      assertThat(networkDisconnected.block(1000)).isTrue();
      assertThat(networkRef.get().getNetworkId()).isEqualTo(42);
      assertThat(statusRef.get().getCode()).isEqualTo(Code.DATA_LOSS);
      assertThat(statusRef.get().getMessage()).isEqualTo("More tests.");

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void createTunFd_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    AtomicReference<TunFdData> tunFdDataRef = new AtomicReference<>();
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public int onKryptonNeedsTunFd(TunFdData tunFdData) {
                tunFdDataRef.set(tunFdData);
                return 54321;
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      TunFdData tunFdData = TunFdData.newBuilder().setMtu(12345).build();
      int fd = notification.createTunFd(tunFdData);

      assertThat(fd).isEqualTo(54321);
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
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public int onKryptonNeedsNetworkFd(NetworkInfo network) {
                networkRef.set(network);
                return 123;
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      NetworkInfo network = NetworkInfo.newBuilder().setNetworkId(321).build();
      int fd = notification.createNetworkFd(network);

      assertThat(fd).isEqualTo(123);
      assertThat(networkRef.get().getNetworkId()).isEqualTo(321);

    } finally {
      krypton.stop();
    }
  }

  @Test
  public void getOauthToken_callsCallback() throws Exception {
    // Set up a listener and condition we can wait on.
    KryptonImpl krypton =
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public String onKryptonNeedsOAuthToken() {
                return "hello world";
              }
            },
            backgroundExecutor);

    try {
      krypton.init();

      String token = notification.getOAuthToken();

      assertThat(token).isEqualTo("hello world");

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
        new KryptonImpl(
            httpFetcher,
            new KryptonAdapter() {
              @Override
              public void onKryptonNeedsIpSecConfiguration(IpSecTransformParams params) {
                condition.open();
              }
            },
            backgroundExecutor);
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
      assertThat(notification.configureIpSec(params)).isTrue();
    } finally {
      krypton.stop();
    }
  }
}
