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

package com.google.android.libraries.privacy.ppn.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.Account;
import android.net.Network;
import android.net.VpnService;
import android.os.Looper;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.flib.robolectric.shadows.ShadowGoogleAuthUtil;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnConnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnListener;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus.Code;
import com.google.android.libraries.privacy.ppn.internal.service.PpnServiceDebugJson;
import com.google.android.libraries.privacy.ppn.krypton.Krypton;
import com.google.android.libraries.privacy.ppn.krypton.KryptonException;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener.NetworkUnavailableReason;
import com.google.android.libraries.privacy.ppn.xenon.Xenon;
import com.google.testing.mockito.Mocks;
import java.time.Duration;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowVpnService;

@Config(shadows = {ShadowGoogleAuthUtil.class, ShadowVpnService.class})
@RunWith(RobolectricTestRunner.class)
public class PpnImplTest {
  private static final String TEST_ACCOUNT_NAME = "test@example.com";

  @Rule public Mocks mocks = new Mocks(this);

  @Mock private PpnAccountManager mockAccountManager;
  @Mock private Krypton mockKrypton;
  @Mock private Xenon mockXenon;
  @Mock private PpnListener mockPpnListener;
  @Mock private PpnTelemetryManager mockTelemetry;
  @Mock private Network mockNetwork;

  private Account account;
  private VpnService service;

  @Before
  public void setUp() {
    account = new Account(TEST_ACCOUNT_NAME, GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
    service = Robolectric.setupService(VpnService.class);
    ShadowGoogleAuthUtil.setAvailableGoogleAccounts(TEST_ACCOUNT_NAME);
    PpnLibrary.clear();
  }

  private PpnImpl createPpn() {
    return createPpn(new PpnOptions.Builder().build());
  }

  private PpnImpl createPpn(PpnOptions options) {
    PpnImpl ppn = new PpnImpl(ApplicationProvider.getApplicationContext(), options);
    // Enable Krypton so that GCS code doesn't run in our tests.
    ppn.setKryptonFactory((ignored1, ignored2) -> mockKrypton);
    ppn.setXenon(mockXenon);
    return ppn;
  }

  @Test
  public void onPpnStarted_usesAccountCachedFromEnablePpn() throws Exception {
    PpnImpl ppn = createPpn();

    // Start PPN to get the account cached.
    ppn.start(account);

    // Set up a listener for when the service starts.
    final AtomicReference<Boolean> onPpnStartedCalled = new AtomicReference<>(false);
    final AtomicReference<Account> startedAccount = new AtomicReference<>(null);
    final AtomicReference<Boolean> neededNotification = new AtomicReference<>(false);
    ppn.setPpnListener(
        new PpnListener() {
          @Override
          public void onPpnStarted(Account account, boolean needsNotification) {
            onPpnStartedCalled.set(true);
            startedAccount.set(account);
            neededNotification.set(needsNotification);
          }

          @Override
          public void onPpnStopped(PpnStatus ppnStatus) {}
        });

    try {
      // Call the service start to trigger the listener.
      assertThat(ppn.isRunning()).isFalse();
      await(ppn.onStartService(service));
      assertThat(ppn.isRunning()).isTrue();

      // Verify that the correct account was used.
      assertThat(onPpnStartedCalled.get()).isTrue();
      assertThat(startedAccount.get()).isSameInstanceAs(account);
      assertThat(neededNotification.get()).isTrue();
    } finally {
      ppn.onStopService();
    }
  }

  @Test
  public void onPpnStarted_looksUpAccountWhenNotCached() throws Exception {
    PpnImpl ppn = createPpn();

    // Enable PPN to set the account.
    ppn.start(account);
    // Clear the cached entry.
    ppn.clearCachedAccount();

    // Set up a listener for when the service starts.
    final AtomicReference<Boolean> onPpnStartedCalled = new AtomicReference<>(false);
    final AtomicReference<Account> startedAccount = new AtomicReference<>(null);
    final AtomicReference<Boolean> neededNotification = new AtomicReference<>(false);
    ppn.setPpnListener(
        new PpnListener() {
          @Override
          public void onPpnStarted(Account account, boolean needsNotification) {
            onPpnStartedCalled.set(true);
            startedAccount.set(account);
            neededNotification.set(needsNotification);
          }

          @Override
          public void onPpnStopped(PpnStatus ppnStatus) {}
        });

    try {
      // Call the service start to trigger the listener.
      assertThat(ppn.isRunning()).isFalse();
      await(ppn.onStartService(service));
      assertThat(ppn.isRunning()).isTrue();

      // Verify that the correct account was used.
      assertThat(onPpnStartedCalled.get()).isTrue();
      assertThat(startedAccount.get().name).isEqualTo(account.name);
      assertThat(startedAccount.get().type).isEqualTo(account.type);
      assertThat(startedAccount.get()).isNotSameInstanceAs(account);
      assertThat(neededNotification.get()).isTrue();
    } finally {
      ppn.onStopService();
    }
  }

  @Test
  public void onStartService_startsKrypton() throws Exception {
    String expectedZincUrl = "ZINC_URL";
    String expectedZincPublicSigningUrl = "ZINC_PSK_URL";
    String expectedBrassUrl = "BRASS_URL";
    String expectedToken = "TOKEN";
    String expectedServiceType = "g1";
    boolean expectedIpsecDatapath = true;
    boolean expectedBridgeOverPpn = true;
    int expectedCipherSuiteKeyLength = 256;

    when(mockAccountManager.getOAuthToken(any(), eq(account), anyString()))
        .thenReturn(expectedToken);

    PpnOptions options =
        new PpnOptions.Builder()
            .setZincUrl(expectedZincUrl)
            .setZincPublicSigningKeyUrl(expectedZincPublicSigningUrl)
            .setBrassUrl(expectedBrassUrl)
            .setIpSecEnabled(expectedIpsecDatapath)
            .setBridgeOnPpnEnabled(expectedBridgeOverPpn)
            .setBridgeKeyLength(expectedCipherSuiteKeyLength)
            .setAccountManager(mockAccountManager)
            .build();
    PpnImpl ppn = createPpn(options);

    // Call start to set the account.
    ppn.start(account);

    // Set up a listener for when the service starts.
    TaskCompletionSource<Void> ppnConnected = new TaskCompletionSource<>();
    doAnswer(
            invocation -> {
              ppnConnected.trySetResult(null);
              return null;
            })
        .when(mockKrypton)
        .start(any());

    // Start the service, then wait for Krypton to get called.
    await(ppn.onStartService(service));
    await(ppnConnected.getTask());

    // Verify that Krypton.start() was called correctly.
    ArgumentCaptor<KryptonConfig> configCaptor = ArgumentCaptor.forClass(KryptonConfig.class);
    verify(mockKrypton).start(configCaptor.capture());
    KryptonConfig config = configCaptor.getValue();
    assertThat(config.getZincUrl()).isEqualTo(expectedZincUrl);
    assertThat(config.getZincPublicSigningKeyUrl()).isEqualTo(expectedZincPublicSigningUrl);
    assertThat(config.getBrassUrl()).isEqualTo(expectedBrassUrl);
    assertThat(config.getServiceType()).isEqualTo(expectedServiceType);
    assertThat(config.getIpsecDatapath()).isEqualTo(expectedIpsecDatapath);
    assertThat(config.getBridgeOverPpn()).isEqualTo(expectedBridgeOverPpn);
    assertThat(config.getCipherSuiteKeyLength()).isEqualTo(expectedCipherSuiteKeyLength);

    // Stop Krypton.
    ppn.onStopService();

    // Verify that Krypton.stop() was called correctly.
    verify(mockKrypton).stop();
    verify(mockKrypton, Mockito.atLeast(0)).getDebugJson();
    verifyNoMoreInteractions(mockKrypton);
  }

  @Test
  public void stop_stopsKrypton() throws Exception {
    String expectedZincUrl = "ZINC_URL";
    String expectedBrassUrl = "BRASS_URL";
    String expectedToken = "TOKEN";
    String expectedServiceType = "g1";

    when(mockAccountManager.getOAuthToken(any(), eq(account), anyString()))
        .thenReturn(expectedToken);

    PpnOptions options =
        new PpnOptions.Builder()
            .setZincUrl(expectedZincUrl)
            .setBrassUrl(expectedBrassUrl)
            .setAccountManager(mockAccountManager)
            .build();
    PpnImpl ppn = createPpn(options);

    // Call start to set the account.
    ppn.start(account);

    // Set up a listener for when the service starts.
    TaskCompletionSource<Void> ppnConnected = new TaskCompletionSource<>();
    doAnswer(
            invocation -> {
              ppnConnected.trySetResult(null);
              return null;
            })
        .when(mockKrypton)
        .start(any());

    // Start the service, then wait for Krypton to get called.
    await(ppn.onStartService(service));
    await(ppnConnected.getTask());

    // Verify that Krypton.start() was called correctly.
    ArgumentCaptor<KryptonConfig> configCaptor = ArgumentCaptor.forClass(KryptonConfig.class);
    verify(mockKrypton).start(configCaptor.capture());
    KryptonConfig config = configCaptor.getValue();
    assertThat(config.getZincUrl()).isEqualTo(expectedZincUrl);
    assertThat(config.getBrassUrl()).isEqualTo(expectedBrassUrl);
    assertThat(config.getServiceType()).isEqualTo(expectedServiceType);

    // Stop PPN.
    ppn.stop();

    // Verify that Krypton.stop() was called correctly.
    verify(mockKrypton).stop();
    verify(mockKrypton, Mockito.atLeast(0)).getDebugJson();
    verifyNoMoreInteractions(mockKrypton);
    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();
  }

  @Test
  public void stop_stopsServiceIfKryptonStopThrows() throws Exception {
    String expectedZincUrl = "ZINC_URL";
    String expectedBrassUrl = "BRASS_URL";
    String expectedToken = "TOKEN";
    String expectedServiceType = "g1";

    when(mockAccountManager.getOAuthToken(any(), eq(account), anyString()))
        .thenReturn(expectedToken);
    doThrow(new KryptonException("Test")).when(mockKrypton).stop();

    PpnOptions options =
        new PpnOptions.Builder()
            .setZincUrl(expectedZincUrl)
            .setBrassUrl(expectedBrassUrl)
            .setAccountManager(mockAccountManager)
            .build();
    PpnImpl ppn = createPpn(options);

    // Call start to set the account.
    ppn.start(account);

    // Set up a listener for when the service starts.
    TaskCompletionSource<Void> ppnConnected = new TaskCompletionSource<>();
    doAnswer(
            invocation -> {
              ppnConnected.trySetResult(null);
              return null;
            })
        .when(mockKrypton)
        .start(any());

    // Start the service, then wait for Krypton to get called.
    await(ppn.onStartService(service));
    await(ppnConnected.getTask());

    // Verify that Krypton.start() was called correctly.
    ArgumentCaptor<KryptonConfig> configCaptor = ArgumentCaptor.forClass(KryptonConfig.class);
    verify(mockKrypton).start(configCaptor.capture());
    KryptonConfig config = configCaptor.getValue();
    assertThat(config.getZincUrl()).isEqualTo(expectedZincUrl);
    assertThat(config.getBrassUrl()).isEqualTo(expectedBrassUrl);
    assertThat(config.getServiceType()).isEqualTo(expectedServiceType);

    // Stop PPN.
    ppn.stop();

    // Verify that Krypton.stop() was called correctly.
    verify(mockKrypton).stop();
    verify(mockKrypton, Mockito.atLeast(0)).getDebugJson();
    verifyNoMoreInteractions(mockKrypton);
    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();
  }

  @Test
  public void options_populateKryptonConfig() {
    PpnOptions options =
        new PpnOptions.Builder()
            .setZincUrl("a")
            .setZincPublicSigningKeyUrl("psk")
            .setBrassUrl("b")
            .setZincOAuthScopes("c")
            .setZincServiceType("d")
            .setBridgeKeyLength(128)
            .setBridgeOnPpnEnabled(true)
            .setBlindSigningEnabled(true)
            .setShouldInstallKryptonCrashSignalHandler(true)
            .setCopperControllerAddress("e")
            .setIpSecEnabled(true)
            .setRekeyDuration(Duration.ofMillis(1005))
            .setReconnectorInitialTimeToReconnect(Duration.ofMillis(2))
            .setReconnectorSessionConnectionDeadline(Duration.ofMillis(4))
            .build();

    KryptonConfig config = PpnImpl.createKryptonConfig(options);

    assertThat(config.getZincUrl()).isEqualTo("a");
    assertThat(config.getZincPublicSigningKeyUrl()).isEqualTo("psk");
    assertThat(config.getBrassUrl()).isEqualTo("b");
    assertThat(config.getServiceType()).isEqualTo("d");
    assertThat(config.getCipherSuiteKeyLength()).isEqualTo(128);
    assertThat(config.getBridgeOverPpn()).isTrue();
    assertThat(config.getEnableBlindSigning()).isTrue();
    assertThat(config.getInstallCrashSignalHandler()).isTrue();
    assertThat(config.getCopperControllerAddress()).isEqualTo("e");
    assertThat(config.getIpsecDatapath()).isTrue();
    assertThat(config.getRekeyDuration().getSeconds()).isEqualTo(1);
    assertThat(config.getRekeyDuration().getNanos()).isEqualTo(5000000);
    assertThat(config.hasReconnectorConfig()).isTrue();
    assertThat(config.getReconnectorConfig().getInitialTimeToReconnectMsec()).isEqualTo(2);
    assertThat(config.getReconnectorConfig().getSessionConnectionDeadlineMsec()).isEqualTo(4);
  }

  @Test
  public void emptyOtions_populateKryptonConfig() {
    PpnOptions options = new PpnOptions.Builder().build();

    KryptonConfig config = PpnImpl.createKryptonConfig(options);

    assertThat(config.getZincUrl()).isNotEmpty();
    assertThat(config.getBrassUrl()).isNotEmpty();
    assertThat(config.getServiceType()).isNotEmpty();
    assertThat(config.hasCipherSuiteKeyLength()).isFalse();
    assertThat(config.hasBridgeOverPpn()).isFalse();
    assertThat(config.hasEnableBlindSigning()).isFalse();
    assertThat(config.hasInstallCrashSignalHandler()).isFalse();
    assertThat(config.hasCopperControllerAddress()).isFalse();
    assertThat(config.hasIpsecDatapath()).isFalse();
    assertThat(config.hasRekeyDuration()).isFalse();
    assertThat(config.hasReconnectorConfig()).isTrue();
    assertThat(config.getReconnectorConfig().hasInitialTimeToReconnectMsec()).isFalse();
    assertThat(config.getReconnectorConfig().hasSessionConnectionDeadlineMsec()).isFalse();
  }

  @Test
  public void onKryptonConnected_notifiesTelemetry() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setTelemetryManager(mockTelemetry);

    ConnectionStatus status = ConnectionStatus.getDefaultInstance();
    ppn.onKryptonConnected(status);
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockTelemetry).notifyConnected();
    verifyNoMoreInteractions(mockTelemetry);
  }

  @Test
  public void onKryptonDisconnected_notifiesTelemetry() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setTelemetryManager(mockTelemetry);

    PpnStatus status = new PpnStatus(Code.OK, "OK");
    ppn.onKryptonDisconnected(status);
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockTelemetry).notifyDisconnected();
    verifyNoMoreInteractions(mockTelemetry);
  }

  @Test
  public void onKryptonConnected_callsOnPpnConnected() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);

    ConnectionStatus status = ConnectionStatus.getDefaultInstance();
    ppn.onKryptonConnected(status);
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnConnected(any(PpnConnectionStatus.class));
  }

  @Test
  public void onKryptonDisconnected_callsOnPpnDisconnected() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);

    PpnStatus status = new PpnStatus(Code.OK, "OK");
    ppn.onKryptonDisconnected(status);
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnDisconnected(status);
  }

  @Test
  public void onKryptonStatusUpdated_callsOnPpnStatusUpdated() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);

    ConnectionStatus status = ConnectionStatus.getDefaultInstance();
    ppn.onKryptonStatusUpdated(status);
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnStatusUpdated(any(PpnConnectionStatus.class));
  }

  @Test
  public void onKryptonPermanentFailure_stopsService() {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);
    ppn.onStartService(service);
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();

    ppn.onKryptonPermanentFailure(new PpnStatus(Code.OK, "OK"));
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();
  }

  @Test
  public void startAndStop_notifyTelemetry() {
    PpnImpl ppn = createPpn();
    ppn.setTelemetryManager(mockTelemetry);
    await(ppn.onStartService(service));
    verify(mockTelemetry).notifyStarted();
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();

    // Outside of tests, PpnVpnService would call this in Service.onDestroy().
    ppn.onStopService();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockTelemetry).notifyStopped();
    verifyNoMoreInteractions(mockTelemetry);
  }

  @Test
  public void onKryptonPermanentFailure_statusIsPassedToListener() {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);
    await(ppn.onStartService(service));
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();

    PpnStatus status = new PpnStatus(Code.INVALID_ARGUMENT, "Test");
    ppn.onKryptonPermanentFailure(status);
    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();

    // Outside of tests, PpnVpnService would call this in Service.onDestroy().
    ppn.onStopService();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnStopped(status);
  }

  @Test
  public void onKryptonStopped_statusIsUnknownIfKryptonIsntStopped() {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);
    await(ppn.onStartService(service));
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();

    // Outside of tests, PpnVpnService would call this in Service.onDestroy().
    ppn.onStopService();
    shadowOf(Looper.getMainLooper()).idle();

    ArgumentCaptor<PpnStatus> status = ArgumentCaptor.forClass(PpnStatus.class);
    verify(mockPpnListener).onPpnStopped(status.capture());
    assertThat(status.getValue().getCode()).isEqualTo(Code.UNKNOWN);
  }

  @Test
  public void onKryptonStopped_statusIsOkIfKryptonStopThrowsOnStop() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);
    await(ppn.onStartService(service));
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();
    doThrow(new KryptonException("Test")).when(mockKrypton).stop();

    ppn.stop();
    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();

    // Outside of tests, PpnVpnService would call this in Service.onDestroy().
    ppn.onStopService();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnStopped(PpnStatus.STATUS_OK);
  }

  @Test
  public void onKryptonPermanentFailure_statusIsKeptIfKryptonStopThrowsOnStopService()
      throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setPpnListener(mockPpnListener);
    await(ppn.onStartService(service));
    assertThat(shadowOf(service).isStoppedBySelf()).isFalse();

    PpnStatus status = new PpnStatus(Code.INVALID_ARGUMENT, "Test");
    ppn.onKryptonPermanentFailure(status);
    assertThat(shadowOf(service).isStoppedBySelf()).isTrue();

    doThrow(new KryptonException("Test")).when(mockKrypton).stop();

    // Outside of tests, PpnVpnService would call this in Service.onDestroy().
    ppn.onStopService();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPpnListener).onPpnStopped(status);
  }

  @Test
  public void onNetworkAvailable_notifiesTelemetry() {
    PpnImpl ppn = createPpn();
    ppn.setTelemetryManager(mockTelemetry);

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    ppn.onNetworkAvailable(ppnNetwork);

    verify(mockTelemetry).notifyNetworkAvailable();
    verifyNoMoreInteractions(mockTelemetry);
  }

  @Test
  public void onNetworkUnavailable_notifiesTelemetry() {
    PpnImpl ppn = createPpn();
    ppn.setTelemetryManager(mockTelemetry);

    ppn.onNetworkUnavailable(NetworkUnavailableReason.UNKNOWN);

    verify(mockTelemetry).notifyNetworkUnavailable();
    verifyNoMoreInteractions(mockTelemetry);
  }

  @Test
  public void getDebugInfo_isPopulated() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setKryptonFactory((ignored1, ignored2) -> mockKrypton);
    ppn.setXenon(mockXenon);
    JSONObject xenonInfo = new JSONObject();
    JSONObject kryptonInfo = new JSONObject();
    doReturn(kryptonInfo).when(mockKrypton).getDebugJson();
    doReturn(xenonInfo).when(mockXenon).getDebugJson();

    JSONObject debugInfo = ppn.getDebugJson();

    assertThat(
            debugInfo.optJSONObject(PpnDebugJson.SERVICE).optBoolean(PpnServiceDebugJson.RUNNING))
        .isFalse();
    assertThat(debugInfo.opt(PpnDebugJson.XENON)).isSameInstanceAs(xenonInfo);
    assertThat(debugInfo.opt(PpnDebugJson.KRYPTON)).isNull();

    try {
      await(ppn.onStartService(service));
      debugInfo = ppn.getDebugJson();

      assertThat(
              debugInfo.optJSONObject(PpnDebugJson.SERVICE).optBoolean(PpnServiceDebugJson.RUNNING))
          .isTrue();
      assertThat(debugInfo.opt(PpnDebugJson.XENON)).isSameInstanceAs(xenonInfo);
      assertThat(debugInfo.opt(PpnDebugJson.KRYPTON)).isSameInstanceAs(kryptonInfo);

    } finally {
      ppn.onStopService();
    }
  }

  @Test
  public void logDebugInfoAsync_getsDebugInfo() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setKryptonFactory((ignored1, ignored2) -> mockKrypton);
    ppn.setXenon(mockXenon);
    JSONObject xenonInfo = new JSONObject();
    JSONObject kryptonInfo = new JSONObject();
    doReturn(kryptonInfo).when(mockKrypton).getDebugJson();
    doReturn(xenonInfo).when(mockXenon).getDebugJson();

    Task<JSONObject> logged = ppn.logDebugInfoAsync(Duration.ofSeconds(30));
    JSONObject debugInfo = await(logged);

    assertThat(
            debugInfo.optJSONObject(PpnDebugJson.SERVICE).optBoolean(PpnServiceDebugJson.RUNNING))
        .isFalse();
    assertThat(debugInfo.opt(PpnDebugJson.XENON)).isSameInstanceAs(xenonInfo);
    assertThat(debugInfo.opt(PpnDebugJson.KRYPTON)).isNull();

    try {
      await(ppn.onStartService(service));
      logged = ppn.logDebugInfoAsync(Duration.ofSeconds(30));
      debugInfo = await(logged);

      assertThat(
              debugInfo.optJSONObject(PpnDebugJson.SERVICE).optBoolean(PpnServiceDebugJson.RUNNING))
          .isTrue();
      assertThat(debugInfo.opt(PpnDebugJson.XENON)).isSameInstanceAs(xenonInfo);
      assertThat(debugInfo.opt(PpnDebugJson.KRYPTON)).isSameInstanceAs(kryptonInfo);

    } finally {
      ppn.onStopService();
    }
  }

  @Test
  public void logDebugInfoAsync_timesOut() throws Exception {
    PpnImpl ppn = createPpn();
    ppn.setKryptonFactory((ignored1, ignored2) -> mockKrypton);
    ppn.setXenon(mockXenon);

    // Make Xenon hang for a second when debug info is requested.
    doAnswer(
            invocation -> {
              try {
                Thread.sleep(1000);
              } catch (InterruptedException e) {
                // There's really nothing to do here.
              }
              return null;
            })
        .when(mockXenon)
        .getDebugJson();

    // Start the async logging.
    Task<JSONObject> logged = ppn.logDebugInfoAsync(Duration.ofMillis(1));

    // Idle the looper to make it go ahead and timeout.
    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(2));

    // The Task should be failed now.
    assertThat(logged.isSuccessful()).isFalse();
    assertThat(logged.getException()).isInstanceOf(TimeoutException.class);
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
