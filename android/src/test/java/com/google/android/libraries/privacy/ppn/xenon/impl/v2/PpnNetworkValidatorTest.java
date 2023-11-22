// Copyright 2023 Google LLC
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

package com.google.android.libraries.privacy.ppn.xenon.impl.v2;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.ConditionVariable;
import android.os.Looper;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.gms.tasks.Task;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowConnectivityManager;
import org.robolectric.shadows.ShadowNetwork;
import org.robolectric.shadows.ShadowNetworkCapabilities;

@RunWith(RobolectricTestRunner.class)
public final class PpnNetworkValidatorTest {
  private static final String CONNECTIVITY_CHECK_URL = "http://gstatic_internet_check_url";

  // These global IP addresses are just random IPv4 and IPv6 addresses.
  private static final String GLOBAL_IPV4_ADDRESS = "129.207.59.194";
  private static final String GLOBAL_IPV6_ADDRESS = "ea0c:c690:7770:acdd:3b69:8fe6:e36e:4a4a";
  private static final String LINK_LOCAL_IPV6_ADDRESS = "fe80::1";

  private PpnNetworkValidator ppnNetworkValidator;

  private ShadowConnectivityManager shadowConnectivityManager;
  private Context context;
  private Network wifiAndroidNetwork;
  private Network cellAndroidNetwork;
  private PpnNetwork wifiPpnNetwork;
  private PpnNetwork cellPpnNetwork;

  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  @Mock PpnNetworkValidator.NetworkValidationListener networkValidationListener;
  @Mock private NetworkInfo wifiNetworkInfo;
  @Mock private NetworkInfo cellNetworkInfo;
  @Mock private HttpFetcher mockHttpFetcher;
  @Mock private PpnOptions mockPpnOptions;
  @Mock private LinkAddress ipv4LinkAddress;
  @Mock private LinkAddress ipv6LinkAddress;

  @Before
  public void setUp() {
    ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor();
    when(mockPpnOptions.getBackgroundExecutor()).thenReturn(backgroundExecutor);
    when(mockPpnOptions.getConnectivityCheckUrl()).thenReturn(CONNECTIVITY_CHECK_URL);
    when(mockPpnOptions.getConnectivityCheckMaxRetries()).thenReturn(3);
    when(mockPpnOptions.getConnectivityCheckRetryDelay()).thenReturn(Duration.ofSeconds(15));

    wifiAndroidNetwork = ShadowNetwork.newInstance(/* netId= */ 1);
    cellAndroidNetwork = ShadowNetwork.newInstance(/* netId= */ 2);

    wifiPpnNetwork = new PpnNetwork(wifiAndroidNetwork, NetworkType.WIFI);
    cellPpnNetwork = new PpnNetwork(cellAndroidNetwork, NetworkType.CELLULAR);

    context = ApplicationProvider.getApplicationContext();
    shadowConnectivityManager =
        shadowOf((ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE));

    // Assume all tested networks are valid from Android unless otherwise set in the specific test.
    shadowConnectivityManager.setNetworkCapabilities(
        wifiAndroidNetwork, ShadowNetworkCapabilities.newInstance());
    shadowConnectivityManager.setNetworkCapabilities(
        cellAndroidNetwork, ShadowNetworkCapabilities.newInstance());

    shadowConnectivityManager.addNetwork(wifiAndroidNetwork, wifiNetworkInfo);
    shadowConnectivityManager.addNetwork(cellAndroidNetwork, cellNetworkInfo);

    when(wifiNetworkInfo.getType()).thenReturn(ConnectivityManager.TYPE_WIFI);
    when(cellNetworkInfo.getType()).thenReturn(ConnectivityManager.TYPE_MOBILE);
    when(wifiNetworkInfo.isConnected()).thenReturn(true);
    when(cellNetworkInfo.isConnected()).thenReturn(true);

    when(mockHttpFetcher.checkGet(eq(CONNECTIVITY_CHECK_URL), any(Network.class), any()))
        .thenReturn(true);

    ppnNetworkValidator =
        new PpnNetworkValidator(
            context, networkValidationListener, mockHttpFetcher, mockPpnOptions);
  }

  @Test
  public void validateNetwork_validatesCellV4V6() throws Exception {
    await(ppnNetworkValidator.validateNetwork(cellPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(cellPpnNetwork), eq(AddressFamily.V4V6));
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, cellAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, cellAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_withNullLinkProperties_validatesWifiV4V6() throws Exception {
    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4V6));
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_withFailedV6Test_validatesWifiV4() throws Exception {
    when(mockHttpFetcher.checkGet(
            eq(CONNECTIVITY_CHECK_URL), any(Network.class), eq(AddressFamily.V6)))
        .thenReturn(false);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4));
  }

  @Test
  public void validateNetwork_withFailedV4Test_validatesWifiV6() throws Exception {
    when(mockHttpFetcher.checkGet(
            eq(CONNECTIVITY_CHECK_URL), any(Network.class), eq(AddressFamily.V4)))
        .thenReturn(false);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V6));
  }

  @Test
  public void validateNetwork_withGlobalV4V6Addresses_validatesWifiV4V6() throws Exception {
    when(ipv4LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV4_ADDRESS));
    when(ipv6LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV6_ADDRESS));
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv4LinkAddress, ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4V6));
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_withGlobalV4Address_validatesWifiV4() throws Exception {
    when(ipv4LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV4_ADDRESS));
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv4LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4));
  }

  @Test
  public void validateNetwork_withGlobalV6Address_validatesWifiV6() throws Exception {
    when(ipv6LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV6_ADDRESS));
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V6));
  }

  @Test
  public void validateNetwork_withGlobalV4AndLocalV6Address_validatesWifiV4() throws Exception {
    when(ipv4LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV4_ADDRESS));
    when(ipv6LinkAddress.getAddress()).thenReturn(Inet6Address.getLoopbackAddress());
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv4LinkAddress, ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4));
  }

  @Test
  public void validateNetwork_withLocalV4AndGlobalV6Address_validatesWifiV6() throws Exception {
    when(ipv4LinkAddress.getAddress()).thenReturn(Inet4Address.getLoopbackAddress());
    when(ipv6LinkAddress.getAddress()).thenReturn(InetAddress.getByName(GLOBAL_IPV6_ADDRESS));
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv4LinkAddress, ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V6));
  }

  @Test
  public void validateNetwork_withLocalV4V6Addresses_doesNotValidateWifi() throws Exception {
    when(ipv4LinkAddress.getAddress()).thenReturn(Inet4Address.getLoopbackAddress());
    when(ipv6LinkAddress.getAddress()).thenReturn(Inet6Address.getLoopbackAddress());
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv4LinkAddress, ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, never()).validationPassed(any(), any());
  }

  @Test
  public void validateNetwork_withLinkLocalV6Addresses_doesNotValidateWifi() throws Exception {
    when(ipv6LinkAddress.getAddress()).thenReturn(InetAddress.getByName(LINK_LOCAL_IPV6_ADDRESS));
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setLinkAddresses(Arrays.asList(ipv6LinkAddress));
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, linkProperties);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, never()).validationPassed(any(), any());
  }

  @Test
  public void validateNetwork_withNoV4V6Addresses_doesNotValidateWifi() throws Exception {
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, new LinkProperties());

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, never()).validationPassed(any(), any());
  }

  @Test
  public void validateNetwork_encounteringExceptions_doesNotValidateWifi() throws Exception {
    when(mockHttpFetcher.checkGet(any(), any(), any())).thenThrow(new RuntimeException());

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, never()).validationPassed(any(), any());
  }

  @Test
  public void validateNetwork_retriesOnFailure() throws Exception {
    // Mock the connectivity check to be false and then true.
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4))
        .thenReturn(false)
        .thenReturn(true);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6))
        .thenReturn(false)
        .thenReturn(true);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener).validationPassed(eq(wifiPpnNetwork), eq(AddressFamily.V4V6));
    verify(mockHttpFetcher, times(2))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher, times(2))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_givesUpAfterContinuedFailure() throws Exception {
    when(mockHttpFetcher.checkGet(eq(CONNECTIVITY_CHECK_URL), eq(wifiAndroidNetwork), any()))
        .thenReturn(false);

    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, never()).validationPassed(any(), any());
    verify(mockHttpFetcher, times(4))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher, times(4))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_multipleValidationsOnOneNetwork() throws Exception {
    ConditionVariable checkGetStarted = new ConditionVariable(false);
    ConditionVariable secondValidationStarted = new ConditionVariable(false);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4))
        .thenReturn(false);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6))
        .thenAnswer(
            invocation -> {
              checkGetStarted.open();
              secondValidationStarted.block();
              return false;
            });

    Task<Boolean> task1 = ppnNetworkValidator.validateNetwork(wifiPpnNetwork);
    checkGetStarted.block();
    Task<Boolean> task2 = ppnNetworkValidator.validateNetwork(wifiPpnNetwork);
    secondValidationStarted.open();
    await(task1);
    await(task2);

    verify(mockHttpFetcher, times(8))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher, times(8))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_validationNotHandledIfClearNetworkValidationCalled()
      throws Exception {
    ConditionVariable checkGetStarted = new ConditionVariable(false);
    ConditionVariable clearValidationCalled = new ConditionVariable(false);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6))
        .thenAnswer(
            invocation -> {
              checkGetStarted.open();
              clearValidationCalled.block();
              return true;
            });

    Task<Boolean> task = ppnNetworkValidator.validateNetwork(wifiPpnNetwork);
    checkGetStarted.block();
    ppnNetworkValidator.clearNetworkValidation(wifiPpnNetwork);
    clearValidationCalled.open();
    assertThat(await(task)).isFalse();

    verify(networkValidationListener, never()).validationPassed(any(), any());
  }

  @Test
  public void validateNetwork_willNotValidateNetworkTwice() throws Exception {
    assertThat(await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork))).isTrue();
    assertThat(await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork))).isTrue();

    verify(networkValidationListener).validationPassed(any(), any());
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void validateNetwork_withSuccessfulValidation_resultIsTrue() throws Exception {
    assertThat(await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork))).isTrue();
  }

  @Test
  public void validateNetwork_withFailedValidation_resultIsFalse() throws Exception {
    // Set the link properties with no link addresses so that validation fails.
    shadowConnectivityManager.setLinkProperties(wifiAndroidNetwork, new LinkProperties());

    assertThat(await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork))).isFalse();
  }

  @Test
  public void clearNetworkValidation_cancelsAllPendingValidations() throws Exception {
    ConditionVariable checkGetStarted = new ConditionVariable(false);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4))
        .thenReturn(false);
    when(mockHttpFetcher.checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6))
        .thenAnswer(
            invocation -> {
              checkGetStarted.open();
              return false;
            });

    Task<Boolean> task = ppnNetworkValidator.validateNetwork(wifiPpnNetwork);
    checkGetStarted.block();
    ppnNetworkValidator.clearNetworkValidation(wifiPpnNetwork);
    await(task);

    verify(networkValidationListener, never()).validationPassed(any(), any());
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher).checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  @Test
  public void clearNetworkValidation_allowsNetworkToBeValidatedAgain() throws Exception {
    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));
    ppnNetworkValidator.clearNetworkValidation(wifiPpnNetwork);
    await(ppnNetworkValidator.validateNetwork(wifiPpnNetwork));

    verify(networkValidationListener, times(2)).validationPassed(eq(wifiPpnNetwork), any());
    verify(mockHttpFetcher, times(2))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V4);
    verify(mockHttpFetcher, times(2))
        .checkGet(CONNECTIVITY_CHECK_URL, wifiAndroidNetwork, AddressFamily.V6);
  }

  /**
   * Blocks until the given task is complete. This can't use Tasks.await, because the async work may
   * need to run on the main thread.
   */
  @CanIgnoreReturnValue
  private static <T> T await(Task<T> task) {
    while (!task.isComplete()) {
      // Allow the main looper to clear itself out.
      shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1));
    }
    shadowOf(Looper.getMainLooper()).idle();
    return task.getResult();
  }
}
