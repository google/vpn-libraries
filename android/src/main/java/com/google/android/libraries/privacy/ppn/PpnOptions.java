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

import android.os.Build;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import com.google.android.libraries.privacy.ppn.internal.ReconnectorConfig;
import com.google.android.libraries.privacy.ppn.proto.IkeV2AuthMethod;
import com.google.android.libraries.privacy.ppn.proto.IkeV2ClientIdType;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Options for configuring how PPN runs. */
public class PpnOptions {
  private static final String TAG = "PpnOptions";
  private static final String DEFAULT_ZINC_URL = "https://staging.zinc.cloud.cupronickel.goog/auth";
  private static final String DEFAULT_ZINC_PUBLIC_SIGNING_KEY_URL =
      "https://staging.zinc.cloud.cupronickel.goog/publickey";
  private static final String DEFAULT_BRASS_URL =
      "https://staging.brass.cloud.cupronickel.goog/addegress";
  private static final String DEFAULT_ZINC_OAUTH_SCOPES =
      "oauth2:https://www.googleapis.com/auth/subscriptions email profile";
  private static final String DEFAULT_ZINC_SERVICE_TYPE = "g1";
  private static final String DEFAULT_INITIAL_DATA_URL =
      "https://staging-phosphor-pa.sandbox.googleapis.com/v1/getInitialData";
  private static final String DEFAULT_BRASS_UPDATE_PATH_INFO_URL =
      "https://staging.brass.cloud.cupronickel.goog:443/updatepathinfo";

  // Default URL to use for checking for internet connectivity. This gstatic url returns no content
  // so it's a very low latency connection check.
  private static final String DEFAULT_CONNECTIVITY_CHECK_URL =
      "https://connectivitycheck.gstatic.com/generate_204";
  private static final Duration DEFAULT_CONNECTIVITY_CHECK_RETRY_DELAY = Duration.ofSeconds(15);
  private static final int DEFAULT_CONNECTIVITY_CHECK_MAX_RETRIES = 5;
  private static final Duration DEFAULT_INITIAL_VALIDATION_RETRY_DELAY = Duration.ofMillis(50);
  private static final int DEFAULT_VALIDATION_MAX_ATTEMPTS = 10;

  private static final String DEFAULT_COPPER_HOSTNAME_SUFFIX = "g-tun.com";

  private final String zincUrl;
  private final String zincPublicSigningKeyUrl;
  private final String brassUrl;
  private final String zincOAuthScopes;
  private final String zincServiceType;
  private final String initialDataUrl;
  private final String updatePathInfoUrl;

  private final String connectivityCheckUrl;
  private final Duration connectivityCheckRetryDelay;
  private final int connectivityCheckMaxRetries;
  private final Duration initialValidationRetryDelay;
  private final int validationMaxAttempts;

  private final Optional<String> copperControllerAddress;
  private final Optional<String> copperHostnameOverride;
  private final List<String> copperHostnameSuffix;

  private final Optional<DatapathProtocol> datapathProtocol;
  private final Optional<Integer> bridgeKeyLength;
  private final Optional<Duration> rekeyDuration;
  private final Optional<Boolean> blindSigningEnabled;
  private final boolean ipv6Enabled;
  private final boolean dynamicMtuEnabled;
  private final boolean socketKeepaliveEnabled;

  private final Optional<Duration> reconnectorInitialTimeToReconnect;
  private final Optional<Duration> reconnectorSessionConnectionDeadline;

  private final boolean isStickyService;
  private boolean safeDisconnectEnabled;
  private Optional<IpGeoLevel> ipGeoLevel;

  private final Set<String> disallowedApplications;
  private final boolean allowBypass;
  private final boolean excludeLocalAddresses;

  private final boolean dnsCacheEnabled;
  private final ExecutorService backgroundExecutor;
  private final Optional<PpnAccountManager> accountManager;
  private final boolean accountRefreshWorkerEnabled;
  private final boolean integrityAttestationEnabled;
  private final boolean hardwareAttestationEnabled;
  private final Optional<Long> attestationCloudProjectNumber;

  private final Optional<String> apiKey;
  private final boolean attachOauthTokenAsHeader;

  private final Optional<Duration> ipv4KeepaliveInterval;
  private final Optional<Duration> ipv6KeepaliveInterval;

  private final Optional<Boolean> publicMetadataEnabled;

  private final Optional<Boolean> debugModeAllowed;

  private final boolean periodicHealthCheckEnabled;
  private final Optional<Duration> periodicHealthCheckDuration;
  private final Optional<String> periodicHealthCheckUrl;
  private final Optional<Integer> periodicHealthCheckPort;

  private final Optional<Boolean> datapathConnectingTimerEnabled;
  private final Optional<Duration> datapathConnectingTimerDuration;

  private final boolean preferOasis;
  private final Optional<Boolean> useReservedIpPool;

  private final boolean attestationNetworkOverrideEnabled;
  private final boolean forceDisallowPlayStoreForAttestationEnabled;

  private final boolean xenonV2Enabled;

  private final Optional<IkeV2AuthMethod> authMethod;
  private final Optional<IkeV2ClientIdType> clientIdType;

  private PpnOptions(PpnOptions.Builder builder) {
    this.zincUrl = builder.zincUrl;
    this.zincPublicSigningKeyUrl = builder.zincPublicSigningKeyUrl;
    this.brassUrl = builder.brassUrl;
    this.zincOAuthScopes = builder.zincOAuthScopes;
    this.zincServiceType = builder.zincServiceType;
    this.initialDataUrl = builder.initialDataUrl;
    this.updatePathInfoUrl = builder.updatePathInfoUrl;

    this.connectivityCheckUrl = builder.connectivityCheckUrl;
    this.connectivityCheckRetryDelay = builder.connectivityCheckRetryDelay;
    this.connectivityCheckMaxRetries = builder.connectivityCheckMaxRetries;
    this.initialValidationRetryDelay = builder.initialValidationRetryDelay;
    this.validationMaxAttempts = builder.validationMaxAttempts;

    this.copperControllerAddress = builder.copperControllerAddress;
    this.copperHostnameOverride = builder.copperHostnameOverride;
    this.copperHostnameSuffix = builder.copperHostnameSuffix;

    this.datapathProtocol = builder.datapathProtocol;
    this.bridgeKeyLength = builder.bridgeKeyLength;
    this.rekeyDuration = builder.rekeyDuration;
    this.blindSigningEnabled = builder.blindSigningEnabled;

    this.reconnectorInitialTimeToReconnect = builder.reconnectorInitialTimeToReconnect;
    this.reconnectorSessionConnectionDeadline = builder.reconnectorSessionConnectionDeadline;

    this.isStickyService = builder.isStickyService;
    this.safeDisconnectEnabled = builder.safeDisconnectEnabled;
    this.ipGeoLevel = builder.ipGeoLevel;
    this.ipv6Enabled = builder.ipv6Enabled;
    this.dynamicMtuEnabled = builder.dynamicMtuEnabled;
    this.socketKeepaliveEnabled = builder.socketKeepaliveEnabled;

    this.disallowedApplications = Collections.unmodifiableSet(builder.disallowedApplications);
    this.allowBypass = builder.allowBypass;
    this.excludeLocalAddresses = builder.excludeLocalAddresses;

    this.dnsCacheEnabled = builder.dnsCacheEnabled;
    this.backgroundExecutor =
        builder.backgroundExecutor.isPresent()
            ? builder.backgroundExecutor.get()
            : Executors.newSingleThreadExecutor();
    this.accountManager = builder.accountManager;
    this.accountRefreshWorkerEnabled = builder.accountRefreshWorkerEnabled;
    this.integrityAttestationEnabled = builder.integrityAttestationEnabled;
    this.hardwareAttestationEnabled = builder.hardwareAttestationEnabled;
    this.attestationCloudProjectNumber = builder.attestationCloudProjectNumber;
    this.apiKey = builder.apiKey;
    this.attachOauthTokenAsHeader = builder.attachOauthTokenAsHeader;

    this.ipv4KeepaliveInterval = builder.ipv4KeepaliveInterval;
    this.ipv6KeepaliveInterval = builder.ipv6KeepaliveInterval;

    this.publicMetadataEnabled = builder.publicMetadataEnabled;

    this.debugModeAllowed = builder.debugModeAllowed;

    this.periodicHealthCheckEnabled = builder.periodicHealthCheckEnabled;
    this.periodicHealthCheckDuration = builder.periodicHealthCheckDuration;
    this.periodicHealthCheckUrl = builder.periodicHealthCheckUrl;
    this.periodicHealthCheckPort = builder.periodicHealthCheckPort;

    this.datapathConnectingTimerEnabled = builder.datapathConnectingTimerEnabled;
    this.datapathConnectingTimerDuration = builder.datapathConnectingTimerDuration;

    this.preferOasis = builder.preferOasis;
    this.useReservedIpPool = builder.useReservedIpPool;

    this.attestationNetworkOverrideEnabled = builder.attestationNetworkOverrideEnabled;
    this.forceDisallowPlayStoreForAttestationEnabled =
        builder.forceDisallowPlayStoreForAttestationEnabled;

    this.xenonV2Enabled = builder.xenonV2Enabled;

    this.authMethod = builder.authMethod;
    this.clientIdType = builder.clientIdType;
  }

  public String getZincUrl() {
    return zincUrl;
  }

  public String getZincPublicSigningKeyUrl() {
    return zincPublicSigningKeyUrl;
  }

  public String getBrassUrl() {
    return brassUrl;
  }

  public String getZincOAuthScopes() {
    return zincOAuthScopes;
  }

  public String getZincServiceType() {
    return zincServiceType;
  }

  public String getInitialDataUrl() {
    return initialDataUrl;
  }

  public String getUpdatePathInfoUrl() {
    return updatePathInfoUrl;
  }

  public String getConnectivityCheckUrl() {
    return connectivityCheckUrl;
  }

  public Duration getConnectivityCheckRetryDelay() {
    return connectivityCheckRetryDelay;
  }

  public int getConnectivityCheckMaxRetries() {
    return connectivityCheckMaxRetries;
  }

  public Duration getInitialValidationRetryDelay() {
    return initialValidationRetryDelay;
  }

  public int getValidationMaxAttempts() {
    return validationMaxAttempts;
  }

  public Optional<String> getCopperControllerAddress() {
    return copperControllerAddress;
  }

  public Optional<String> getCopperHostnameOverride() {
    return copperHostnameOverride;
  }

  public List<String> getCopperHostnameSuffix() {
    return copperHostnameSuffix;
  }

  public Optional<DatapathProtocol> getDatapathProtocol() {
    return datapathProtocol;
  }

  public Optional<Integer> getBridgeKeyLength() {
    return bridgeKeyLength;
  }

  public Optional<Duration> getRekeyDuration() {
    return rekeyDuration;
  }

  public Optional<Boolean> isBlindSigningEnabled() {
    return blindSigningEnabled;
  }

  public boolean isIPv6Enabled() {
    return ipv6Enabled;
  }

  public boolean isDynamicMtuEnabled() {
    return dynamicMtuEnabled;
  }

  public boolean isSocketKeepaliveEnabled() {
    return socketKeepaliveEnabled;
  }

  public Optional<Duration> getReconnectorInitialTimeToReconnect() {
    return reconnectorInitialTimeToReconnect;
  }

  public Optional<Duration> getReconnectorSessionConnectionDeadline() {
    return reconnectorSessionConnectionDeadline;
  }

  public boolean isStickyService() {
    return isStickyService;
  }

  public boolean isSafeDisconnectEnabled() {
    return safeDisconnectEnabled;
  }

  public void setSafeDisconnectEnabled(boolean enabled) {
    safeDisconnectEnabled = enabled;
  }

  public Optional<IpGeoLevel> getIpGeoLevel() {
    return ipGeoLevel;
  }

  public void setIpGeoLevel(IpGeoLevel level) {
    ipGeoLevel = Optional.of(level);
  }

  public Set<String> getDisallowedApplications() {
    return disallowedApplications;
  }

  public boolean allowBypass() {
    return allowBypass;
  }

  public boolean excludeLocalAddresses() {
    return excludeLocalAddresses;
  }

  public boolean isDnsCacheEnabled() {
    return dnsCacheEnabled;
  }

  public ExecutorService getBackgroundExecutor() {
    return backgroundExecutor;
  }

  public Optional<PpnAccountManager> getAccountManager() {
    return accountManager;
  }

  public boolean isAccountRefreshWorkerEnabled() {
    return accountRefreshWorkerEnabled;
  }

  public boolean isIntegrityAttestationEnabled() {
    return integrityAttestationEnabled;
  }

  public boolean isHardwareAttestationEnabled() {
    return hardwareAttestationEnabled;
  }

  public Optional<Long> getAttestationCloudProjectNumber() {
    return attestationCloudProjectNumber;
  }

  public Optional<String> getApiKey() {
    return apiKey;
  }

  public boolean isAttachOauthTokenAsHeaderEnabled() {
    return attachOauthTokenAsHeader;
  }

  public Optional<Duration> getIpv4KeepaliveInterval() {
    return ipv4KeepaliveInterval;
  }

  public Optional<Duration> getIpv6KeepaliveInterval() {
    return ipv6KeepaliveInterval;
  }

  public Optional<Boolean> isPublicMetadataEnabled() {
    return publicMetadataEnabled;
  }

  public Optional<Boolean> isDebugModeAllowed() {
    return debugModeAllowed;
  }

  public boolean isPeriodicHealthCheckEnabled() {
    return periodicHealthCheckEnabled;
  }

  public Optional<Duration> getPeriodicHealthCheckDuration() {
    return periodicHealthCheckDuration;
  }

  public Optional<String> getPeriodicHealthCheckUrl() {
    return periodicHealthCheckUrl;
  }

  public Optional<Integer> getPeriodicHealthCheckPort() {
    return periodicHealthCheckPort;
  }

  public Optional<Boolean> getDatapathConnectingTimerEnabled() {
    return datapathConnectingTimerEnabled;
  }

  public Optional<Duration> getDatapathConnectingTimerDuration() {
    return datapathConnectingTimerDuration;
  }

  public boolean isOasisPreferred() {
    return preferOasis;
  }

  public Optional<Boolean> getUseReservedIpPool() {
    return useReservedIpPool;
  }

  public boolean isAttestationNetworkOverrideEnabled() {
    return attestationNetworkOverrideEnabled;
  }

  public boolean isForceDisallowPlayStoreForAttestationEnabled() {
    return forceDisallowPlayStoreForAttestationEnabled;
  }

  public boolean isXenonV2Enabled() {
    return xenonV2Enabled;
  }

  public Optional<IkeV2AuthMethod> getAuthMethod() {
    return authMethod;
  }

  public Optional<IkeV2ClientIdType> getClientIdType() {
    return clientIdType;
  }

  /** Creates a KryptonConfig.Builder using the current options. */
  public KryptonConfig.Builder createKryptonConfigBuilder() {
    ReconnectorConfig.Builder reconnectorBuilder = ReconnectorConfig.newBuilder();
    getReconnectorInitialTimeToReconnect()
        .ifPresent(
            duration ->
                reconnectorBuilder.setInitialTimeToReconnectMsec((int) duration.toMillis()));
    getReconnectorSessionConnectionDeadline()
        .ifPresent(
            duration ->
                reconnectorBuilder.setSessionConnectionDeadlineMsec((int) duration.toMillis()));
    ReconnectorConfig reconnectorConfig = reconnectorBuilder.build();

    KryptonConfig.Builder builder =
        KryptonConfig.newBuilder()
            .setZincUrl(getZincUrl())
            .setZincPublicSigningKeyUrl(getZincPublicSigningKeyUrl())
            .setBrassUrl(getBrassUrl())
            .setServiceType(getZincServiceType())
            .setInitialDataUrl(getInitialDataUrl())
            .setUpdatePathInfoUrl(getUpdatePathInfoUrl())
            .setReconnectorConfig(reconnectorConfig)
            .setPreferOasis(isOasisPreferred())
            .addAllCopperHostnameSuffix(getCopperHostnameSuffix())
            .setSafeDisconnectEnabled(isSafeDisconnectEnabled())
            .setIpv6Enabled(isIPv6Enabled())
            .setDynamicMtuEnabled(isDynamicMtuEnabled())
            .setIntegrityAttestationEnabled(isIntegrityAttestationEnabled())
            .setAttachOauthTokenAsHeader(isAttachOauthTokenAsHeaderEnabled())
            .setPeriodicHealthCheckEnabled(isPeriodicHealthCheckEnabled());

    getCopperControllerAddress().ifPresent(builder::setCopperControllerAddress);
    getCopperHostnameOverride().ifPresent(builder::setCopperHostnameOverride);
    getDatapathProtocol()
        .ifPresent(protocol -> builder.setDatapathProtocol(protocol.kryptonConfigValue()));

    // Default to bridge if the current Android API Level does not support IPsec
    if (builder.getDatapathProtocol() == KryptonConfig.DatapathProtocol.IPSEC
        && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      Log.w(TAG, "Android version does not support IPsec datapath. Defaulting to Bridge.");
      builder.setDatapathProtocol(KryptonConfig.DatapathProtocol.BRIDGE);
    }

    getBridgeKeyLength().ifPresent(builder::setCipherSuiteKeyLength);
    isBlindSigningEnabled().ifPresent(builder::setEnableBlindSigning);

    getRekeyDuration().ifPresent(duration -> builder.setRekeyDuration(toProtoDuration(duration)));

    getIpGeoLevel().ifPresent(builder::setIpGeoLevel);
    getApiKey().ifPresent(builder::setApiKey);

    getIpv4KeepaliveInterval()
        .ifPresent(interval -> builder.setIpv4KeepaliveInterval(toProtoDuration(interval)));
    getIpv6KeepaliveInterval()
        .ifPresent(interval -> builder.setIpv6KeepaliveInterval(toProtoDuration(interval)));

    isPublicMetadataEnabled().ifPresent(builder::setPublicMetadataEnabled);
    isDebugModeAllowed().ifPresent(builder::setDebugModeAllowed);

    getPeriodicHealthCheckDuration()
        .ifPresent(duration -> builder.setPeriodicHealthCheckDuration(toProtoDuration(duration)));

    getPeriodicHealthCheckUrl().ifPresent(builder::setPeriodicHealthCheckUrl);
    getPeriodicHealthCheckPort().ifPresent(builder::setPeriodicHealthCheckPort);
    getDatapathConnectingTimerEnabled().ifPresent(builder::setDatapathConnectingTimerEnabled);

    getDatapathConnectingTimerDuration()
        .ifPresent(
            duration -> builder.setDatapathConnectingTimerDuration(toProtoDuration(duration)));

    getUseReservedIpPool().ifPresent(builder::setUseReservedIpPool);

    getAuthMethod().ifPresent(builder::setAuthMethod);
    getClientIdType().ifPresent(builder::setClientIdType);

    return builder;
  }

  /** A Builder for creating a PpnOptions. */
  public static class Builder {
    private String zincUrl = DEFAULT_ZINC_URL;
    private String zincPublicSigningKeyUrl = DEFAULT_ZINC_PUBLIC_SIGNING_KEY_URL;
    private String brassUrl = DEFAULT_BRASS_URL;
    private String zincOAuthScopes = DEFAULT_ZINC_OAUTH_SCOPES;
    private String zincServiceType = DEFAULT_ZINC_SERVICE_TYPE;
    private String initialDataUrl = DEFAULT_INITIAL_DATA_URL;
    private String updatePathInfoUrl = DEFAULT_BRASS_UPDATE_PATH_INFO_URL;
    private String connectivityCheckUrl = DEFAULT_CONNECTIVITY_CHECK_URL;
    private Duration connectivityCheckRetryDelay = DEFAULT_CONNECTIVITY_CHECK_RETRY_DELAY;
    private int connectivityCheckMaxRetries = DEFAULT_CONNECTIVITY_CHECK_MAX_RETRIES;
    private Duration initialValidationRetryDelay = DEFAULT_INITIAL_VALIDATION_RETRY_DELAY;
    private int validationMaxAttempts = DEFAULT_VALIDATION_MAX_ATTEMPTS;
    private Optional<String> copperControllerAddress = Optional.empty();
    private Optional<String> copperHostnameOverride = Optional.empty();
    private List<String> copperHostnameSuffix = ImmutableList.of(DEFAULT_COPPER_HOSTNAME_SUFFIX);

    private Optional<DatapathProtocol> datapathProtocol = Optional.empty();
    private Optional<Integer> bridgeKeyLength = Optional.empty();
    private Optional<Duration> rekeyDuration = Optional.empty();
    private Optional<Boolean> blindSigningEnabled = Optional.empty();

    private Optional<Duration> reconnectorInitialTimeToReconnect = Optional.empty();
    private Optional<Duration> reconnectorSessionConnectionDeadline = Optional.empty();

    private boolean isStickyService = false;
    private boolean safeDisconnectEnabled = false;
    private Optional<IpGeoLevel> ipGeoLevel = Optional.empty();
    private boolean ipv6Enabled = true;
    private boolean dynamicMtuEnabled = false;
    private boolean socketKeepaliveEnabled = true;

    private Set<String> disallowedApplications = ImmutableSet.of();
    private boolean allowBypass = false;
    private boolean excludeLocalAddresses = true;

    private boolean dnsCacheEnabled = true;
    private Optional<ExecutorService> backgroundExecutor = Optional.empty();
    private Optional<PpnAccountManager> accountManager = Optional.empty();
    private boolean accountRefreshWorkerEnabled = true;
    private boolean integrityAttestationEnabled = false;
    private boolean hardwareAttestationEnabled = false;
    private Optional<Long> attestationCloudProjectNumber = Optional.empty();

    private Optional<String> apiKey = Optional.empty();
    private boolean attachOauthTokenAsHeader = false;

    private Optional<Duration> ipv4KeepaliveInterval = Optional.empty();
    private Optional<Duration> ipv6KeepaliveInterval = Optional.empty();

    private Optional<Boolean> publicMetadataEnabled = Optional.empty();

    private Optional<Boolean> debugModeAllowed = Optional.empty();

    private boolean periodicHealthCheckEnabled = false;
    private Optional<Duration> periodicHealthCheckDuration = Optional.empty();
    private Optional<String> periodicHealthCheckUrl = Optional.empty();
    private Optional<Integer> periodicHealthCheckPort = Optional.empty();

    private Optional<Boolean> datapathConnectingTimerEnabled = Optional.empty();
    private Optional<Duration> datapathConnectingTimerDuration = Optional.empty();

    private boolean attestationNetworkOverrideEnabled = false;
    private boolean forceDisallowPlayStoreForAttestationEnabled = false;

    private boolean preferOasis = false;
    private Optional<Boolean> useReservedIpPool = Optional.empty();

    private boolean xenonV2Enabled = false;

    private Optional<IkeV2AuthMethod> authMethod = Optional.empty();
    private Optional<IkeV2ClientIdType> clientIdType = Optional.empty();

    public Builder() {}

    /**
     * Sets the url to use for connecting to the Zinc backend, such as
     * "https://autopush.zinc.cloud.cupronickel.goog:443/auth".
     *
     * <p>If this is not set, it will default to a reasonable Zinc server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setZincUrl(String url) {
      if (!isNullOrEmpty(url)) {
        this.zincUrl = url;
      }
      return this;
    }

    /**
     * Sets the url to use for connecting to the Zinc backend for public signing key, such as
     * "https://autopush.zinc.cloud.cupronickel.goog:443/publickey".
     *
     * <p>If this is not set, it will default to a reasonable Zinc server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setZincPublicSigningKeyUrl(String url) {
      if (!isNullOrEmpty(url)) {
        this.zincPublicSigningKeyUrl = url;
      }
      return this;
    }

    /**
     * Sets the url to use for connecting to the Brass backend, such as
     * "https://autopush.brass.cloud.cupronickel.goog:443/addegress".
     *
     * <p>If this is not set, it will default to a reasonable Brass server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setBrassUrl(String url) {
      if (!isNullOrEmpty(url)) {
        this.brassUrl = url;
      }
      return this;
    }

    /**
     * Sets the oauth scopes to use for authenticating with the Zinc backend.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setZincOAuthScopes(String scopes) {
      if (!isNullOrEmpty(scopes)) {
        this.zincOAuthScopes = scopes;
      }
      return this;
    }

    /**
     * Sets the oauth scopes to use for authenticating with the Zinc backend.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setZincServiceType(String type) {
      if (!isNullOrEmpty(type)) {
        this.zincServiceType = type;
      }
      return this;
    }

    /**
     * Sets the url to use for connecting to the Phosphor backend for get initial data, such as
     * "https://autopush-phosphor-pa.sandbox.googleapis.com/v1/getInitialData".
     *
     * <p>If this is not set, it will default to a reasonable Phosphor server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setInitialDataUrl(String url) {
      if (!isNullOrEmpty(url)) {
        this.initialDataUrl = url;
      }
      return this;
    }

    /**
     * Sets the url to use for connecting to the Brass or Beryllium backend for /updatepathinfo
     * endpoint such as "https://staging.brass.cloud.cupronickel.goog:443/updatepathinfo".
     *
     * <p>If this is not set, it will default to a reasonable 'Brass' server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setUpdatePathInfoUrl(String url) {
      if (!isNullOrEmpty(url)) {
        this.updatePathInfoUrl = url;
      }
      return this;
    }

    /**
     * Sets the URL to use in PPN to check whether a Network has internet connectivity or not.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setConnectivityCheckUrl(String connectivityCheckUrl) {
      if (!isNullOrEmpty(connectivityCheckUrl)) {
        this.connectivityCheckUrl = connectivityCheckUrl;
      }
      return this;
    }

    /**
     * Sets how long to wait before rechecking whether a Network has internet connectivity or not,
     * if it previously did not.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setConnectivityCheckRetryDelay(Duration retryDelay) {
      if (retryDelay != null) {
        this.connectivityCheckRetryDelay = retryDelay;
      }
      return this;
    }

    /**
     * Sets initial delay to retry network validation after a failure.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setInitialValidationRetryDelay(Duration retryDelay) {
      if (retryDelay != null) {
        this.initialValidationRetryDelay = retryDelay;
      }
      return this;
    }

    /**
     * Sets how many times to try network validation for a network before giving up.
     *
     * <p>If this is not set, it will default to a reasonable value.
     */
    @CanIgnoreReturnValue
    public Builder setValidationMaxAttempts(int maxAttempts) {
      this.validationMaxAttempts = maxAttempts;
      return this;
    }

    /**
     * Sets how many times to recheck whether a Network has internet connectivity, before assuming
     * it will not get internet without an intervening network event from Android.
     *
     * <p>If this is not set, it will default to a reasonable value.
     */
    @CanIgnoreReturnValue
    public Builder setConnectivityCheckMaxRetries(int maxRetries) {
      this.connectivityCheckMaxRetries = maxRetries;
      return this;
    }

    /**
     * Sets the DNS address or v4/v6 address of the copper controller.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setCopperControllerAddress(String address) {
      if (!isNullOrEmpty(address)) {
        this.copperControllerAddress = Optional.of(address);
      }
      return this;
    }

    /**
     * Sets a copper hostname override for testing purposes.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setCopperHostnameOverride(String address) {
      if (!isNullOrEmpty(address)) {
        this.copperHostnameOverride = Optional.of(address);
      }
      return this;
    }

    /**
     * Sets the copper hostname suffix list.
     *
     * <p>If null list is passed in, it will be ignored.
     *
     * <p>Empty element will be ignored too.
     */
    @CanIgnoreReturnValue
    public Builder setCopperHostnameSuffix(List<String> suffixList) {
      if (suffixList != null) {
        List<String> copperSuffix = new ArrayList<>();
        for (String suffix : suffixList) {
          if (!suffix.isEmpty()) {
            copperSuffix.add(suffix);
          }
        }
        this.copperHostnameSuffix = copperSuffix;
      }
      return this;
    }

    /** Sets the PPN datapath protocol. */
    @CanIgnoreReturnValue
    public Builder setDatapathProtocol(DatapathProtocol datapathProtocol) {
      this.datapathProtocol = Optional.of(datapathProtocol);
      return this;
    }

    /** Sets the key length to use for the bridge. */
    @CanIgnoreReturnValue
    public Builder setBridgeKeyLength(int length) {
      if (length != 128 && length != 256) {
        throw new IllegalArgumentException("bridge key length must be 128 or 256");
      }
      this.bridgeKeyLength = Optional.of(length);
      return this;
    }

    /**
     * Sets the duration between rekeys. Defaults to 1 day.
     *
     * <p>If null is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setRekeyDuration(Duration duration) {
      this.rekeyDuration = Optional.of(duration);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setBlindSigningEnabled(boolean blindSigningEnabled) {
      this.blindSigningEnabled = Optional.of(blindSigningEnabled);
      return this;
    }

    /** Sets whether Krypton should install a signal handler to help gracefully handle crashes. */
    @CanIgnoreReturnValue
    public Builder setShouldInstallKryptonCrashSignalHandler(boolean value) {
      Log.i(TAG, "Krypton crash signal handler has been deprecated");
      return this;
    }

    /** Sets whether PPN should try to use IPv6 at all. */
    @CanIgnoreReturnValue
    public Builder setIPv6Enabled(boolean ipv6Enabled) {
      this.ipv6Enabled = ipv6Enabled;
      return this;
    }

    /** Sets whether to set MTU dynamically. */
    @CanIgnoreReturnValue
    public Builder setDynamicMtuEnabled(boolean dynamicMtuEnabled) {
      this.dynamicMtuEnabled = dynamicMtuEnabled;
      return this;
    }

    /** Sets whether PPN should attempt to use SocketKeepalive. */
    @CanIgnoreReturnValue
    public Builder setSocketKeepaliveEnabled(boolean socketKeepaliveEnabled) {
      this.socketKeepaliveEnabled = socketKeepaliveEnabled;
      return this;
    }

    /** Sets the initial time between reconnects. */
    @CanIgnoreReturnValue
    public Builder setReconnectorInitialTimeToReconnect(Duration duration) {
      if (duration != null) {
        this.reconnectorInitialTimeToReconnect = Optional.of(duration);
      }
      return this;
    }

    /** Sets the deadline for a session to be established. */
    @CanIgnoreReturnValue
    public Builder setReconnectorSessionConnectionDeadline(Duration duration) {
      if (duration != null) {
        this.reconnectorSessionConnectionDeadline = Optional.of(duration);
      }
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setStickyService(boolean isStickyService) {
      this.isStickyService = isStickyService;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSafeDisconnectEnabled(boolean enabled) {
      this.safeDisconnectEnabled = enabled;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIpGeoLevel(IpGeoLevel level) {
      this.ipGeoLevel = Optional.of(level);
      return this;
    }

    /** Sets the list of apps that will bypass the VPN, as package names. */
    @CanIgnoreReturnValue
    public Builder setDisallowedApplications(Iterable<String> packageNames) {
      HashSet<String> copy = new HashSet<>();
      for (String packageName : packageNames) {
        copy.add(packageName);
      }
      this.disallowedApplications = Collections.unmodifiableSet(copy);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAllowBypass(boolean allowBypass) {
      this.allowBypass = allowBypass;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setExcludeLocalAddresses(boolean excludeLocalAddresses) {
      this.excludeLocalAddresses = excludeLocalAddresses;
      return this;
    }

    /** Sets whether to use an internal DNS cache in the library. */
    @CanIgnoreReturnValue
    public Builder setDnsCacheEnabled(boolean enabled) {
      this.dnsCacheEnabled = enabled;
      return this;
    }

    /** Sets the Executor that PPN should use for most work it needs to do in the background. */
    @CanIgnoreReturnValue
    public Builder setBackgroundExecutor(ExecutorService executor) {
      this.backgroundExecutor = Optional.of(executor);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAccountManager(PpnAccountManager accountManager) {
      this.accountManager = Optional.of(accountManager);
      return this;
    }

    /**
     * Sets whether PPN should schedule a periodic background worker to proactively refresh account
     * credentials.
     */
    @CanIgnoreReturnValue
    public Builder setAccountRefreshWorkerEnabled(boolean enabled) {
      this.accountRefreshWorkerEnabled = enabled;
      return this;
    }

    /** Sets whether PPN should try to perform device validation. */
    @CanIgnoreReturnValue
    public Builder setIntegrityAttestationEnabled(boolean enable) {
      this.integrityAttestationEnabled = enable;
      return this;
    }

    /**
     * Sets whether PPN should try to perform hardware attestation.
     *
     * <p>This flag should be turned on for devices running Keystore 2.0+ or above only. Doing this
     * on a device that does not support Keystore 2.0+ (24+) might result in failed device
     * attestation. Restriction is 23+ because API used in Hardware Attestation was added in API 23.
     */
    @CanIgnoreReturnValue
    @RequiresApi(23)
    public Builder setHardwareAttestationEnabled(boolean enable) {
      if (enable && Build.VERSION.SDK_INT < 23) {
        Log.e(TAG, "Cannot set hardware attestation if API < 23. Ignoring.");
        return this;
      }
      this.hardwareAttestationEnabled = enable;
      return this;
    }

    /** Sets the GCP Project ID that might be necessary for attestation. */
    @CanIgnoreReturnValue
    public Builder setAttestationCloudProjectNumber(long cloudNumber) {
      this.attestationCloudProjectNumber = Optional.of(cloudNumber);
      return this;
    }

    /** Sets the API Key to use in auth requests that don't already have an attach OAuth token. */
    @CanIgnoreReturnValue
    public Builder setApiKey(String apiKey) {
      if (!isNullOrEmpty(apiKey)) {
        this.apiKey = Optional.of(apiKey);
      }
      return this;
    }

    /**
     * Sets whether to attach the OAuth token as a header in http requests, instead of in the body.
     */
    @CanIgnoreReturnValue
    public Builder setAttachOauthTokenAsHeaderEnabled(boolean attachOauthTokenAsHeader) {
      this.attachOauthTokenAsHeader = attachOauthTokenAsHeader;
      return this;
    }

    /**
     * Sets how long to wait for outgoing packets on IPsec connections that are using IPv4 before
     * sending a keepalive packet.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setIpv4KeepaliveInterval(Duration interval) {
      if (interval != null) {
        this.ipv4KeepaliveInterval = Optional.of(interval);
      }
      return this;
    }

    /**
     * Sets how long to wait for outgoing packets on IPsec connections that are using IPv6 before
     * sending a keepalive packet.
     *
     * <p>If this is not set, it will default to a reasonable value.
     *
     * <p>If null is passed in, it will be ignored.
     */
    @CanIgnoreReturnValue
    public Builder setIpv6KeepaliveInterval(Duration interval) {
      if (interval != null) {
        this.ipv6KeepaliveInterval = Optional.of(interval);
      }
      return this;
    }

    /** Sets whether to use Public Metadata in session. */
    @CanIgnoreReturnValue
    public Builder setPublicMetadataEnabled(boolean publicMetadataEnabled) {
      this.publicMetadataEnabled = Optional.of(publicMetadataEnabled);
      return this;
    }

    /** Sets whether debug mode is allowed or not. */
    @CanIgnoreReturnValue
    public Builder setDebugModeAllowed(boolean debugModeAllowed) {
      this.debugModeAllowed = Optional.of(debugModeAllowed);
      return this;
    }

    /** Sets whether to use a periodic health check. */
    @CanIgnoreReturnValue
    public Builder setPeriodicHealthCheckEnabled(boolean periodicHealthCheckEnabled) {
      this.periodicHealthCheckEnabled = periodicHealthCheckEnabled;
      return this;
    }

    /** Sets the duration for the interval for the periodic health check. */
    @CanIgnoreReturnValue
    public Builder setPeriodicHealthCheckDuration(Duration interval) {
      if (interval != null) {
        this.periodicHealthCheckDuration = Optional.of(interval);
      }
      return this;
    }

    /** Sets the URL for the periodic health check. */
    @CanIgnoreReturnValue
    public Builder setPeriodicHealthCheckUrl(String url) {
      if (url != null) {
        this.periodicHealthCheckUrl = Optional.of(url);
      }
      return this;
    }

    /** Sets the port for the periodic health check. */
    @CanIgnoreReturnValue
    public Builder setPeriodicHealthCheckPort(int port) {
      this.periodicHealthCheckPort = Optional.of(port);
      return this;
    }

    /** Sets whether to use the datapath connecting timer. */
    @CanIgnoreReturnValue
    public Builder setDatapathConnectingTimerEnabled(boolean enabled) {
      this.datapathConnectingTimerEnabled = Optional.of(enabled);
      return this;
    }

    /** Sets the duration for the datapath connecting timer. */
    @CanIgnoreReturnValue
    public Builder setDatapathConnectingTimerDuration(Duration interval) {
      if (interval != null) {
        this.datapathConnectingTimerDuration = Optional.of(interval);
      }
      return this;
    }

    /** Sets whether the client prefers Oasis as the dataplane provider. */
    @CanIgnoreReturnValue
    public Builder setPreferOasis(boolean preferOasis) {
      this.preferOasis = preferOasis;
      return this;
    }

    /** Sets whether the client should use reserved (allocated but inactive) IP addresses. */
    @CanIgnoreReturnValue
    public Builder setUseReservedIpPool(boolean useReservedIpPool) {
      this.useReservedIpPool = Optional.of(useReservedIpPool);
      return this;
    }

    /**
     * Whether to pass in a Network override when doing attestation. Once this code path is well
     * tested in production, the option will be removed, and this feature will always be used.
     */
    @CanIgnoreReturnValue
    public Builder setAttestationNetworkOverrideEnabled(boolean enabled) {
      this.attestationNetworkOverrideEnabled = enabled;
      return this;
    }

    /**
     * Whether to automatically force the Play Store to bypass the VPN by adding it to the
     * "disallowed apps" list when attestation is enabled. This is necessary because the Play Store
     * makes calls to retrieve an integrity token, and if the VPN is not connected, it will be
     * blocked, which causes the VPN to become wedged.
     */
    @CanIgnoreReturnValue
    public Builder setForceDisallowPlayStoreForAttestationEnabled(boolean enabled) {
      this.forceDisallowPlayStoreForAttestationEnabled = enabled;
      return this;
    }

    /** Sets whether to use the new version of Xenon. */
    @CanIgnoreReturnValue
    public Builder setXenonV2Enabled(boolean enabled) {
      this.xenonV2Enabled = enabled;
      return this;
    }

    /** Sets the IKEv2 authentication method. */
    @CanIgnoreReturnValue
    public Builder setAuthMethod(IkeV2AuthMethod authMethod) {
      if (authMethod != null) {
        this.authMethod = Optional.of(authMethod);
      }
      return this;
    }

    /** Sets the IKEv2 client ID type. */
    @CanIgnoreReturnValue
    public Builder setClientIdType(IkeV2ClientIdType clientIdType) {
      if (clientIdType != null) {
        this.clientIdType = Optional.of(clientIdType);
      }
      return this;
    }

    /** Returns a new PpnOptions based on the values set in this Builder. */
    public PpnOptions build() {
      return new PpnOptions(this);
    }

    private static boolean isNullOrEmpty(@Nullable String s) {
      return s == null || s.isEmpty();
    }
  }

  /** Defines the Datapath Protocols supported by PPN. */
  public enum DatapathProtocol {
    /** Use IpSec datapath. */
    IPSEC(KryptonConfig.DatapathProtocol.IPSEC),

    /** Use bridge over PPN. */
    BRIDGE(KryptonConfig.DatapathProtocol.BRIDGE),

    /** Use IKE with VpnManager. */
    IKE(KryptonConfig.DatapathProtocol.IKE);

    private final KryptonConfig.DatapathProtocol kryptonConfigValue;

    DatapathProtocol(KryptonConfig.DatapathProtocol kryptonConfigValue) {
      this.kryptonConfigValue = kryptonConfigValue;
    }

    public KryptonConfig.DatapathProtocol kryptonConfigValue() {
      return kryptonConfigValue;
    }
  }

  /** Converts a {@link Duration} to a protobuf {@link com.google.protobuf.Duration}. */
  private static com.google.protobuf.Duration toProtoDuration(Duration duration) {
    return com.google.protobuf.Duration.newBuilder()
        .setSeconds(duration.getSeconds())
        .setNanos(duration.getNano())
        .build();
  }
}
