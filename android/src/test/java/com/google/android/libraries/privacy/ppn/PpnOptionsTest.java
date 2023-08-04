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

package com.google.android.libraries.privacy.ppn;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import java.time.Duration;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link PpnOptions}. */
@RunWith(RobolectricTestRunner.class)
public class PpnOptionsTest {

  @Test
  public void testZincUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getZincUrl()).isNotNull();
    assertThat(options.getZincUrl()).isNotEmpty();
  }

  @Test
  public void setZincUrl_storesUrl() {
    String url = "http://example.com/auth";
    PpnOptions options = new PpnOptions.Builder().setZincUrl(url).build();

    assertThat(options.getZincUrl()).isEqualTo(url);
  }

  @Test
  public void setZincUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setZincUrl(null).build();

    assertThat(options.getZincUrl()).isNotNull();
    assertThat(options.getZincUrl()).isNotEmpty();
  }

  @Test
  public void setZincUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setZincUrl("").build();

    assertThat(options.getZincUrl()).isNotNull();
    assertThat(options.getZincUrl()).isNotEmpty();
  }

  @Test
  public void testZincPublicSigningKeyUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getZincPublicSigningKeyUrl()).isNotNull();
    assertThat(options.getZincPublicSigningKeyUrl()).isNotEmpty();
  }

  @Test
  public void setZincPublicSigningKeyUrl_storesUrl() {
    String url = "http://example.com/publickey";
    PpnOptions options = new PpnOptions.Builder().setZincPublicSigningKeyUrl(url).build();

    assertThat(options.getZincPublicSigningKeyUrl()).isEqualTo(url);
  }

  @Test
  public void setZincPublicSigningKeyUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setZincPublicSigningKeyUrl(null).build();

    assertThat(options.getZincPublicSigningKeyUrl()).isNotNull();
    assertThat(options.getZincPublicSigningKeyUrl()).isNotEmpty();
  }

  @Test
  public void setZincPublicSigningKeyUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setZincPublicSigningKeyUrl("").build();

    assertThat(options.getZincPublicSigningKeyUrl()).isNotNull();
    assertThat(options.getZincPublicSigningKeyUrl()).isNotEmpty();
  }

  @Test
  public void testBrassUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getBrassUrl()).isNotNull();
    assertThat(options.getBrassUrl()).isNotEmpty();
  }

  @Test
  public void setBrassUrl_storesUrl() {
    String url = "http://example.com/auth";
    PpnOptions options = new PpnOptions.Builder().setBrassUrl(url).build();

    assertThat(options.getBrassUrl()).isEqualTo(url);
  }

  @Test
  public void setBrassUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setBrassUrl(null).build();

    assertThat(options.getBrassUrl()).isNotNull();
    assertThat(options.getBrassUrl()).isNotEmpty();
  }

  @Test
  public void setBrassUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setBrassUrl("").build();

    assertThat(options.getBrassUrl()).isNotNull();
    assertThat(options.getBrassUrl()).isNotEmpty();
  }

  @Test
  public void testZincOAuthScopes_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getZincOAuthScopes()).isNotNull();
    assertThat(options.getZincOAuthScopes()).isNotEmpty();
  }

  @Test
  public void setZincOAuthScopes_storesValue() {
    String scopes = "foobar";
    PpnOptions options = new PpnOptions.Builder().setZincOAuthScopes(scopes).build();

    assertThat(options.getZincOAuthScopes()).isEqualTo(scopes);
  }

  @Test
  public void setZincOAuthScopes_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setZincOAuthScopes(null).build();

    assertThat(options.getZincOAuthScopes()).isNotNull();
    assertThat(options.getZincOAuthScopes()).isNotEmpty();
  }

  @Test
  public void setZincOAuthScopes_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setZincOAuthScopes("").build();

    assertThat(options.getZincOAuthScopes()).isNotNull();
    assertThat(options.getZincOAuthScopes()).isNotEmpty();
  }

  @Test
  public void testZincServiceType_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getZincServiceType()).isNotNull();
    assertThat(options.getZincServiceType()).isNotEmpty();
  }

  @Test
  public void setZincServiceType_storesValue() {
    String type = "type";
    PpnOptions options = new PpnOptions.Builder().setZincServiceType(type).build();

    assertThat(options.getZincServiceType()).isEqualTo(type);
  }

  @Test
  public void setZincServiceType_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setZincServiceType(null).build();

    assertThat(options.getZincServiceType()).isNotNull();
    assertThat(options.getZincServiceType()).isNotEmpty();
  }

  @Test
  public void setZincServiceType_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setZincServiceType("").build();

    assertThat(options.getZincServiceType()).isNotNull();
    assertThat(options.getZincServiceType()).isNotEmpty();
  }

  @Test
  public void setInitialDataUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getInitialDataUrl()).isNotNull();
    assertThat(options.getInitialDataUrl()).isNotEmpty();
  }

  @Test
  public void setInitialDataUrl_storesUrl() {
    String url = "http://example.com/v1/getInitialData";
    PpnOptions options = new PpnOptions.Builder().setInitialDataUrl(url).build();

    assertThat(options.getInitialDataUrl()).isEqualTo(url);
  }

  @Test
  public void setInitialDataUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setInitialDataUrl(null).build();

    assertThat(options.getInitialDataUrl()).isNotNull();
    assertThat(options.getInitialDataUrl()).isNotEmpty();
  }

  @Test
  public void setInitialDataUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setInitialDataUrl("").build();

    assertThat(options.getInitialDataUrl()).isNotNull();
    assertThat(options.getInitialDataUrl()).isNotEmpty();
  }

  @Test
  public void setUpdatePathInfoUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getUpdatePathInfoUrl()).isNotNull();
    assertThat(options.getUpdatePathInfoUrl()).isNotEmpty();
  }

  @Test
  public void setUpdatePathInfoUrl_storesUrl() {
    String url = "http://example.com/updatepathinfo";
    PpnOptions options = new PpnOptions.Builder().setUpdatePathInfoUrl(url).build();

    assertThat(options.getUpdatePathInfoUrl()).isEqualTo(url);
  }

  @Test
  public void setUpdatePathInfoUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setUpdatePathInfoUrl(null).build();

    assertThat(options.getUpdatePathInfoUrl()).isNotNull();
    assertThat(options.getUpdatePathInfoUrl()).isNotEmpty();
  }

  @Test
  public void setUpdatePathInfoUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setUpdatePathInfoUrl("").build();

    assertThat(options.getUpdatePathInfoUrl()).isNotNull();
    assertThat(options.getUpdatePathInfoUrl()).isNotEmpty();
  }

  @Test
  public void testConnectivityCheckUrl_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getConnectivityCheckUrl()).isNotNull();
    assertThat(options.getConnectivityCheckUrl()).isNotEmpty();
  }

  @Test
  public void testConnectivityCheckUrl_storesValue() {
    String url = "url";
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckUrl(url).build();

    assertThat(options.getConnectivityCheckUrl()).isEqualTo(url);
  }

  @Test
  public void testConnectivityCheckUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckUrl(null).build();

    assertThat(options.getConnectivityCheckUrl()).isNotNull();
    assertThat(options.getConnectivityCheckUrl()).isNotEmpty();
  }

  @Test
  public void testConnectivityCheckUrl_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckUrl("").build();

    assertThat(options.getConnectivityCheckUrl()).isNotNull();
    assertThat(options.getConnectivityCheckUrl()).isNotEmpty();
  }

  @Test
  public void testConnectivityCheckRetryDelay_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getConnectivityCheckRetryDelay()).isEqualTo(Duration.ofSeconds(15));
  }

  @Test
  public void testConnectivityCheckRetryDelay_storesValue() {
    Duration delay = Duration.ofMillis(1500);
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckRetryDelay(delay).build();

    assertThat(options.getConnectivityCheckRetryDelay()).isEqualTo(delay);
  }

  @Test
  public void testConnectivityCheckRetryDelay_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckRetryDelay(null).build();

    assertThat(options.getConnectivityCheckRetryDelay()).isEqualTo(Duration.ofSeconds(15));
  }

  @Test
  public void testConnectivityCheckMaxRetries_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();

    assertThat(options.getConnectivityCheckMaxRetries()).isEqualTo(5);
  }

  @Test
  public void testConnectivityCheckMaxRetries_storesValue() {
    PpnOptions options = new PpnOptions.Builder().setConnectivityCheckMaxRetries(10).build();

    assertThat(options.getConnectivityCheckMaxRetries()).isEqualTo(10);
  }

  @Test
  public void testCopperControllerAddress_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getCopperControllerAddress()).isEmpty();
  }

  @Test
  public void setCopperControllerAddress_storesValue() {
    String address = "127.0.0.1";
    PpnOptions options = new PpnOptions.Builder().setCopperControllerAddress(address).build();
    assertThat(options.getCopperControllerAddress()).hasValue(address);
  }

  @Test
  public void setCopperControllerAddress_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setCopperControllerAddress(null).build();
    assertThat(options.getCopperControllerAddress()).isEmpty();
  }

  @Test
  public void setCopperControllerAddress_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setCopperControllerAddress("").build();
    assertThat(options.getCopperControllerAddress()).isEmpty();
  }

  @Test
  public void testCopperHostnameOverride_hasDefault() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getCopperHostnameOverride()).isEmpty();
  }

  @Test
  public void setCopperHostnameOverride_storesValue() {
    String address = "127.0.0.1";
    PpnOptions options = new PpnOptions.Builder().setCopperHostnameOverride(address).build();
    assertThat(options.getCopperHostnameOverride()).hasValue(address);
  }

  @Test
  public void setCopperHostnameOverride_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setCopperHostnameOverride(null).build();
    assertThat(options.getCopperHostnameOverride()).isEmpty();
  }

  @Test
  public void setCopperHostnameOverride_ignoresEmpty() {
    PpnOptions options = new PpnOptions.Builder().setCopperHostnameOverride("").build();
    assertThat(options.getCopperHostnameOverride()).isEmpty();
  }

  @Test
  public void setDatapathProtocol_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getDatapathProtocol()).isEmpty();
  }

  @Test
  public void setDatapathProtocol_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.IPSEC).build();
    assertThat(options.getDatapathProtocol()).hasValue(PpnOptions.DatapathProtocol.IPSEC);
  }

  @Test
  public void setBridgeKeyLength_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getBridgeKeyLength()).isEmpty();
  }

  @Test
  public void setBridgeKeyLength_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setBridgeKeyLength(256).build();
    assertThat(options.getBridgeKeyLength()).hasValue(256);
  }

  @Test
  public void setBridgeKeyLength_throwsOnBadValues() {
    assertThrows(
        IllegalArgumentException.class, () -> new PpnOptions.Builder().setBridgeKeyLength(42));
  }

  @Test
  public void setRekeyDuration_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getRekeyDuration()).isEmpty();
  }

  @Test
  public void setRekeyDuration_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setRekeyDuration(Duration.ofMillis(42)).build();
    assertThat(options.getRekeyDuration().get().toMillis()).isEqualTo(42);
  }

  @Test
  public void setBlindSigningEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isBlindSigningEnabled()).isEmpty();
  }

  @Test
  public void setBlindSigningEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setBlindSigningEnabled(true).build();
    assertThat(options.isBlindSigningEnabled().get()).isTrue();
  }

  @Test
  public void setReconnectorInitialTimeToReconnect_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getReconnectorInitialTimeToReconnect()).isEmpty();
  }

  @Test
  public void setReconnectorInitialTimeToReconnect_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder()
            .setReconnectorInitialTimeToReconnect(Duration.ofMillis(42))
            .build();
    assertThat(options.getReconnectorInitialTimeToReconnect().get().toMillis()).isEqualTo(42);
  }

  @Test
  public void setReconnectorSessionConnectionDeadline_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getReconnectorSessionConnectionDeadline()).isEmpty();
  }

  @Test
  public void setReconnectorSessionConnectionDeadline_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder()
            .setReconnectorSessionConnectionDeadline(Duration.ofMillis(42))
            .build();
    assertThat(options.getReconnectorSessionConnectionDeadline().get().toMillis()).isEqualTo(42);
  }

  @Test
  public void setStickyService_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isStickyService()).isFalse();
  }

  @Test
  public void setStickyService_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setStickyService(true).build();
    assertThat(options.isStickyService()).isTrue();
  }

  @Test
  public void setSafeDisconnectEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isSafeDisconnectEnabled()).isFalse();
  }

  @Test
  public void setSafeDisconnectEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setSafeDisconnectEnabled(true).build();
    assertThat(options.isSafeDisconnectEnabled()).isTrue();
  }

  @Test
  public void setIPv6Enabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isIPv6Enabled()).isTrue();
  }

  @Test
  public void setIPv6Enabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setIPv6Enabled(false).build();
    assertThat(options.isIPv6Enabled()).isFalse();
  }

  @Test
  public void disallowedApplications_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getDisallowedApplications()).isNotNull();
    assertThat(options.getDisallowedApplications()).isEmpty();
  }

  @Test
  public void setDisallowedOptions_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder()
            .setDisallowedApplications(Arrays.asList("foo", "bar", "baz"))
            .build();
    assertThat(options.getDisallowedApplications()).containsExactly("foo", "bar", "baz");
  }

  @Test
  public void setDnsCacheEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isDnsCacheEnabled()).isTrue();
  }

  @Test
  public void setDnsCacheEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setDnsCacheEnabled(false).build();
    assertThat(options.isDnsCacheEnabled()).isFalse();
  }

  @Test
  public void setApiKey_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getApiKey()).isEmpty();
  }

  @Test
  public void setApiKey_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setApiKey("apiKey").build();
    assertThat(options.getApiKey()).hasValue("apiKey");
  }

  @Test
  public void setAttachOauthTokenAsHeaderEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isAttachOauthTokenAsHeaderEnabled()).isFalse();
  }

  @Test
  public void setAttachOauthTokenAsHeaderEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setAttachOauthTokenAsHeaderEnabled(true).build();
    assertThat(options.isAttachOauthTokenAsHeaderEnabled()).isTrue();
  }

  @Test
  public void setIpv4KeepaliveInterval_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getIpv4KeepaliveInterval()).isEmpty();
  }

  @Test
  public void setIpv4KeepaliveInterval_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setIpv4KeepaliveInterval(Duration.ofMillis(42)).build();
    assertThat(options.getIpv4KeepaliveInterval()).isPresent();
    assertThat(options.getIpv4KeepaliveInterval().get()).isEqualTo(Duration.ofMillis(42));
  }

  @Test
  public void setIpv6KeepaliveInterval_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getIpv6KeepaliveInterval()).isEmpty();
  }

  @Test
  public void setIpv6KeepaliveInterval_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setIpv6KeepaliveInterval(Duration.ofMillis(42)).build();
    assertThat(options.getIpv6KeepaliveInterval()).isPresent();
    assertThat(options.getIpv6KeepaliveInterval().get()).isEqualTo(Duration.ofMillis(42));
  }

  @Test
  public void createKryptonConfig_setsValues() {
    PpnOptions options =
        new PpnOptions.Builder()
            .setZincUrl("a")
            .setZincPublicSigningKeyUrl("psk")
            .setBrassUrl("b")
            .setZincOAuthScopes("c")
            .setZincServiceType("d")
            .setBridgeKeyLength(128)
            .setDatapathProtocol(PpnOptions.DatapathProtocol.BRIDGE)
            .setBlindSigningEnabled(true)
            .setShouldInstallKryptonCrashSignalHandler(true)
            .setCopperControllerAddress("e")
            .setCopperHostnameOverride("g")
            .setCopperHostnameSuffix(Arrays.asList("f"))
            .setRekeyDuration(Duration.ofMillis(1005))
            .setReconnectorInitialTimeToReconnect(Duration.ofMillis(2))
            .setReconnectorSessionConnectionDeadline(Duration.ofMillis(4))
            .setSafeDisconnectEnabled(true)
            .setIpGeoLevel(IpGeoLevel.CITY)
            .setIPv6Enabled(false)
            .setDynamicMtuEnabled(true)
            .setIntegrityAttestationEnabled(true)
            .setApiKey("apiKey")
            .setAttachOauthTokenAsHeaderEnabled(true)
            .setIpv4KeepaliveInterval(Duration.ofMillis(8))
            .setIpv6KeepaliveInterval(Duration.ofMillis(16))
            .setPublicMetadataEnabled(true)
            .setInitialDataUrl("h")
            .setUpdatePathInfoUrl("i")
            .setDebugModeAllowed(true)
            .setPeriodicHealthCheckEnabled(true)
            .setPeriodicHealthCheckDuration(Duration.ofSeconds(8))
            .setPeriodicHealthCheckUrl("healthCheckUrl")
            .setPeriodicHealthCheckPort(80)
            .setDatapathConnectingTimerEnabled(true)
            .setDatapathConnectingTimerDuration(Duration.ofSeconds(16))
            .build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    assertThat(config.getZincUrl()).isEqualTo("a");
    assertThat(config.getZincPublicSigningKeyUrl()).isEqualTo("psk");
    assertThat(config.getBrassUrl()).isEqualTo("b");
    assertThat(config.getServiceType()).isEqualTo("d");
    assertThat(config.getCipherSuiteKeyLength()).isEqualTo(128);
    assertThat(config.hasEnableBlindSigning()).isTrue();
    assertThat(config.getEnableBlindSigning()).isTrue();
    assertThat(config.getCopperControllerAddress()).isEqualTo("e");
    assertThat(config.getCopperHostnameOverride()).isEqualTo("g");
    assertThat(config.getCopperHostnameSuffixCount()).isEqualTo(1);
    assertThat(config.getCopperHostnameSuffix(0)).isEqualTo("f");
    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.BRIDGE);
    assertThat(config.getRekeyDuration().getSeconds()).isEqualTo(1);
    assertThat(config.getRekeyDuration().getNanos()).isEqualTo(5000000);
    assertThat(config.hasReconnectorConfig()).isTrue();
    assertThat(config.getReconnectorConfig().getInitialTimeToReconnectMsec()).isEqualTo(2);
    assertThat(config.getReconnectorConfig().getSessionConnectionDeadlineMsec()).isEqualTo(4);
    assertThat(config.getSafeDisconnectEnabled()).isTrue();
    assertThat(config.getIpGeoLevel()).isEqualTo(IpGeoLevel.CITY);
    assertThat(config.getIpv6Enabled()).isFalse();
    assertThat(config.getDynamicMtuEnabled()).isTrue();
    assertThat(config.getIntegrityAttestationEnabled()).isTrue();
    assertThat(config.getApiKey()).isEqualTo("apiKey");
    assertThat(config.getAttachOauthTokenAsHeader()).isTrue();
    assertThat(config.hasIpv4KeepaliveInterval()).isTrue();
    assertThat(config.getIpv4KeepaliveInterval().getSeconds()).isEqualTo(0);
    assertThat(config.getIpv4KeepaliveInterval().getNanos()).isEqualTo(8000000);
    assertThat(config.hasIpv6KeepaliveInterval()).isTrue();
    assertThat(config.getIpv6KeepaliveInterval().getSeconds()).isEqualTo(0);
    assertThat(config.getIpv6KeepaliveInterval().getNanos()).isEqualTo(16000000);
    assertThat(config.getPublicMetadataEnabled()).isTrue();
    assertThat(config.getInitialDataUrl()).isEqualTo("h");
    assertThat(config.getUpdatePathInfoUrl()).isEqualTo("i");
    assertThat(config.getDebugModeAllowed()).isTrue();
    assertThat(config.getPeriodicHealthCheckEnabled()).isTrue();
    assertThat(config.hasPeriodicHealthCheckDuration()).isTrue();
    assertThat(config.getPeriodicHealthCheckDuration().getSeconds()).isEqualTo(8);
    assertThat(config.getPeriodicHealthCheckDuration().getNanos()).isEqualTo(0);
    assertThat(config.hasPeriodicHealthCheckUrl()).isTrue();
    assertThat(config.getPeriodicHealthCheckUrl()).isEqualTo("healthCheckUrl");
    assertThat(config.hasPeriodicHealthCheckPort()).isTrue();
    assertThat(config.getPeriodicHealthCheckPort()).isEqualTo(80);
    assertThat(config.hasDatapathConnectingTimerEnabled()).isTrue();
    assertThat(config.getDatapathConnectingTimerEnabled()).isTrue();
    assertThat(config.hasDatapathConnectingTimerDuration()).isTrue();
    assertThat(config.getDatapathConnectingTimerDuration().getSeconds()).isEqualTo(16);
  }

  @Test
  public void createKryptonConfig_defaultValues() {
    PpnOptions options = new PpnOptions.Builder().build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    assertThat(config.getZincUrl()).isNotEmpty();
    assertThat(config.getBrassUrl()).isNotEmpty();
    assertThat(config.getServiceType()).isNotEmpty();
    assertThat(config.hasCipherSuiteKeyLength()).isFalse();
    assertThat(config.hasEnableBlindSigning()).isFalse();
    assertThat(config.hasCopperControllerAddress()).isFalse();
    assertThat(config.hasCopperHostnameOverride()).isFalse();
    assertThat(config.getCopperHostnameSuffixCount()).isEqualTo(1);
    assertThat(config.getCopperHostnameSuffix(0)).isNotEmpty();
    assertThat(config.hasDatapathProtocol()).isFalse();
    assertThat(config.hasRekeyDuration()).isFalse();
    assertThat(config.hasReconnectorConfig()).isTrue();
    assertThat(config.getReconnectorConfig().hasInitialTimeToReconnectMsec()).isFalse();
    assertThat(config.getReconnectorConfig().hasSessionConnectionDeadlineMsec()).isFalse();
    assertThat(config.getSafeDisconnectEnabled()).isFalse();
    assertThat(config.getIpGeoLevel()).isEqualTo(IpGeoLevel.COUNTRY);
    assertThat(config.getIpv6Enabled()).isTrue();
    assertThat(config.getDynamicMtuEnabled()).isFalse();
    assertThat(config.getIntegrityAttestationEnabled()).isFalse();
    assertThat(config.getApiKey()).isEmpty();
    assertThat(config.getAttachOauthTokenAsHeader()).isFalse();
    assertThat(config.hasIpv4KeepaliveInterval()).isFalse();
    assertThat(config.hasIpv6KeepaliveInterval()).isFalse();
    assertThat(config.getPublicMetadataEnabled()).isFalse();
    assertThat(config.getInitialDataUrl()).isNotEmpty();
    assertThat(config.getUpdatePathInfoUrl()).isNotEmpty();
    assertThat(config.getDebugModeAllowed()).isFalse();
    assertThat(config.getPeriodicHealthCheckEnabled()).isFalse();
    assertThat(config.hasPeriodicHealthCheckDuration()).isFalse();
    assertThat(config.hasPeriodicHealthCheckUrl()).isFalse();
    assertThat(config.hasPeriodicHealthCheckPort()).isFalse();
    assertThat(config.hasDatapathConnectingTimerEnabled()).isFalse();
    assertThat(config.hasDatapathConnectingTimerDuration()).isFalse();
  }

  @Test
  public void createKryptonConfig_ipsecProtocolInPpnOptions() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.IPSEC).build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.IPSEC);
  }

  @Test
  public void createKryptonConfig_bridgeProtocolInPpnOptions() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.BRIDGE).build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.BRIDGE);
  }

  @Test
  public void setPublicMetadataEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isPublicMetadataEnabled()).isEmpty();
  }

  @Test
  public void setPublicMetadataEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setPublicMetadataEnabled(true).build();
    assertThat(options.isPublicMetadataEnabled().get()).isTrue();
  }

  @Test
  public void setDebugModeAllowed_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isDebugModeAllowed()).isEmpty();
  }

  @Test
  public void setDebugModeAllowed_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setDebugModeAllowed(true).build();
    assertThat(options.isDebugModeAllowed().get()).isTrue();
  }

  @Test
  public void setPeriodicHealthCheckEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.isPeriodicHealthCheckEnabled()).isFalse();
  }

  @Test
  public void setPeriodicHealthCheckEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setPeriodicHealthCheckEnabled(true).build();
    assertThat(options.isPeriodicHealthCheckEnabled()).isTrue();
  }

  @Test
  public void setPeriodicHealthCheckDuration_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getPeriodicHealthCheckDuration()).isEmpty();
  }

  @Test
  public void setPeriodicHealthCheckDuration_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setPeriodicHealthCheckDuration(Duration.ofSeconds(30)).build();
    assertThat(options.getPeriodicHealthCheckDuration().get().toSeconds()).isEqualTo(30);
  }

  @Test
  public void setPeriodicHealthCheckDuration_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setPeriodicHealthCheckDuration(null).build();
    assertThat(options.getPeriodicHealthCheckDuration()).isEmpty();
  }

  @Test
  public void setPeriodicHealthCheckUrl_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getPeriodicHealthCheckUrl()).isEmpty();
  }

  @Test
  public void setPeriodicHealthCheckUrl_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setPeriodicHealthCheckUrl("healthCheckUrl").build();
    assertThat(options.getPeriodicHealthCheckUrl()).hasValue("healthCheckUrl");
  }

  @Test
  public void setPeriodicHealthCheckUrl_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setPeriodicHealthCheckUrl(null).build();
    assertThat(options.getPeriodicHealthCheckUrl()).isEmpty();
  }

  @Test
  public void setPeriodicHealthCheckPort_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getPeriodicHealthCheckPort()).isEmpty();
  }

  @Test
  public void setPeriodicHealthCheckPort_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setPeriodicHealthCheckPort(80).build();
    assertThat(options.getPeriodicHealthCheckPort()).hasValue(80);
  }

  @Test
  public void setDatapathConnectingTimerEnabled_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getDatapathConnectingTimerEnabled()).isEmpty();
  }

  @Test
  public void setDatapathConnectingTimerEnabled_setsValue() {
    PpnOptions options = new PpnOptions.Builder().setDatapathConnectingTimerEnabled(true).build();
    assertThat(options.getDatapathConnectingTimerEnabled().get()).isTrue();
  }

  @Test
  public void setDatapathConnectingTimerDuration_defaultValue() {
    PpnOptions options = new PpnOptions.Builder().build();
    assertThat(options.getDatapathConnectingTimerDuration()).isEmpty();
  }

  @Test
  public void setDatapathConnectingTimerDuration_setsValue() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathConnectingTimerDuration(Duration.ofSeconds(30)).build();
    assertThat(options.getDatapathConnectingTimerDuration().get().toSeconds()).isEqualTo(30);
  }

  @Test
  public void setDatapathConnectingTimerDuration_ignoresNull() {
    PpnOptions options = new PpnOptions.Builder().setDatapathConnectingTimerDuration(null).build();
    assertThat(options.getDatapathConnectingTimerDuration()).isEmpty();
  }
}
