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

package com.google.android.libraries.privacy.ppn;

import androidx.annotation.Nullable;
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
  private static final String DEFAULT_ZINC_URL = "https://staging.zinc.cloud.cupronickel.goog/auth";
  private static final String DEFAULT_ZINC_PUBLIC_SIGNING_KEY_URL =
      "https://staging.zinc.cloud.cupronickel.goog/publickey";
  private static final String DEFAULT_BRASS_URL =
      "https://staging.brass.cloud.cupronickel.goog/addegress";
  private static final String DEFAULT_ZINC_OAUTH_SCOPES =
      "oauth2:https://www.googleapis.com/auth/subscriptions email profile";
  private static final String DEFAULT_ZINC_SERVICE_TYPE = "g1";

  // Default URL to use for checking for internet connectivity. This gstatic url returns no content
  // so it's a very low latency connection check.
  private static final String DEFAULT_CONNECTIVITY_CHECK_URL =
      "https://connectivitycheck.gstatic.com/generate_204";
  private static final Duration DEFAULT_CONNECTIVITY_CHECK_RETRY_DELAY = Duration.ofSeconds(15);
  private static final int DEFAULT_CONNECTIVITY_CHECK_MAX_RETRIES = 5;

  private static final String DEFAULT_COPPER_HOSTNAME_SUFFIX = "g-tun.com";

  private final String zincUrl;
  private final String zincPublicSigningKeyUrl;
  private final String brassUrl;
  private final String zincOAuthScopes;
  private final String zincServiceType;

  private final String connectivityCheckUrl;
  private final Duration connectivityCheckRetryDelay;
  private final int connectivityCheckMaxRetries;

  private final Optional<String> copperControllerAddress;
  private final List<String> copperHostnameSuffix;

  private final Optional<Boolean> ipSecEnabled;
  private final Optional<Boolean> bridgeOnPpnEnabled;
  private final Optional<Integer> bridgeKeyLength;
  private final Optional<Duration> rekeyDuration;
  private final Optional<Boolean> blindSigningEnabled;
  private final Optional<Boolean> shouldInstallKryptonCrashSignalHandler;

  private final Optional<Duration> reconnectorInitialTimeToReconnect;
  private final Optional<Duration> reconnectorSessionConnectionDeadline;

  private final boolean isStickyService;
  private final boolean safeDisconnectEnabled;

  private final Set<String> disallowedApplications;

  private final boolean dnsCacheEnabled;
  private final ExecutorService backgroundExecutor;
  private final Optional<PpnAccountManager> accountManager;

  private PpnOptions(PpnOptions.Builder builder) {
    this.zincUrl = builder.zincUrl;
    this.zincPublicSigningKeyUrl = builder.zincPublicSigningKeyUrl;
    this.brassUrl = builder.brassUrl;
    this.zincOAuthScopes = builder.zincOAuthScopes;
    this.zincServiceType = builder.zincServiceType;

    this.connectivityCheckUrl = builder.connectivityCheckUrl;
    this.connectivityCheckRetryDelay = builder.connectivityCheckRetryDelay;
    this.connectivityCheckMaxRetries = builder.connectivityCheckMaxRetries;

    this.copperControllerAddress = builder.copperControllerAddress;
    this.copperHostnameSuffix = builder.copperHostnameSuffix;

    this.ipSecEnabled = builder.ipSecEnabled;
    this.bridgeOnPpnEnabled = builder.bridgeOnPpnEnabled;
    this.bridgeKeyLength = builder.bridgeKeyLength;
    this.rekeyDuration = builder.rekeyDuration;
    this.blindSigningEnabled = builder.blindSigningEnabled;
    this.shouldInstallKryptonCrashSignalHandler = builder.shouldInstallKryptonCrashSignalHandler;

    this.reconnectorInitialTimeToReconnect = builder.reconnectorInitialTimeToReconnect;
    this.reconnectorSessionConnectionDeadline = builder.reconnectorSessionConnectionDeadline;

    this.isStickyService = builder.isStickyService;
    this.safeDisconnectEnabled = builder.safeDisconnectEnabled;

    this.disallowedApplications = Collections.unmodifiableSet(builder.disallowedApplications);

    this.dnsCacheEnabled = builder.dnsCacheEnabled;
    this.backgroundExecutor =
        builder.backgroundExecutor.isPresent()
            ? builder.backgroundExecutor.get()
            : Executors.newSingleThreadExecutor();
    this.accountManager = builder.accountManager;
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

  public String getConnectivityCheckUrl() {
    return connectivityCheckUrl;
  }

  public Duration getConnectivityCheckRetryDelay() {
    return connectivityCheckRetryDelay;
  }

  public int getConnectivityCheckMaxRetries() {
    return connectivityCheckMaxRetries;
  }

  public Optional<String> getCopperControllerAddress() {
    return copperControllerAddress;
  }

  public List<String> getCopperHostnameSuffix() {
    return copperHostnameSuffix;
  }

  public Optional<Boolean> isIpSecEnabled() {
    return ipSecEnabled;
  }

  public Optional<Boolean> isBridgeOnPpnEnabled() {
    return bridgeOnPpnEnabled;
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

  public Optional<Boolean> shouldInstallKryptonCrashSignalHandler() {
    return shouldInstallKryptonCrashSignalHandler;
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

  public Set<String> getDisallowedApplications() {
    return disallowedApplications;
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

  /** A Builder for creating a PpnOptions. */
  public static class Builder {
    private String zincUrl = DEFAULT_ZINC_URL;
    private String zincPublicSigningKeyUrl = DEFAULT_ZINC_PUBLIC_SIGNING_KEY_URL;
    private String brassUrl = DEFAULT_BRASS_URL;
    private String zincOAuthScopes = DEFAULT_ZINC_OAUTH_SCOPES;
    private String zincServiceType = DEFAULT_ZINC_SERVICE_TYPE;
    private String connectivityCheckUrl = DEFAULT_CONNECTIVITY_CHECK_URL;
    private Duration connectivityCheckRetryDelay = DEFAULT_CONNECTIVITY_CHECK_RETRY_DELAY;
    private int connectivityCheckMaxRetries = DEFAULT_CONNECTIVITY_CHECK_MAX_RETRIES;
    private Optional<String> copperControllerAddress = Optional.empty();
    private List<String> copperHostnameSuffix = List.of(DEFAULT_COPPER_HOSTNAME_SUFFIX);

    private Optional<Boolean> ipSecEnabled = Optional.empty();
    private Optional<Boolean> bridgeOnPpnEnabled = Optional.empty();
    private Optional<Integer> bridgeKeyLength = Optional.empty();
    private Optional<Duration> rekeyDuration = Optional.empty();
    private Optional<Boolean> blindSigningEnabled = Optional.empty();
    private Optional<Boolean> shouldInstallKryptonCrashSignalHandler = Optional.empty();

    private Optional<Duration> reconnectorInitialTimeToReconnect = Optional.empty();
    private Optional<Duration> reconnectorSessionConnectionDeadline = Optional.empty();

    private boolean isStickyService = false;
    private boolean safeDisconnectEnabled = false;

    private Set<String> disallowedApplications = Collections.emptySet();

    private boolean dnsCacheEnabled = true;
    private Optional<ExecutorService> backgroundExecutor = Optional.empty();
    private Optional<PpnAccountManager> accountManager = Optional.empty();

    public Builder() {}

    /**
     * Sets the url to use for connecting to the Zinc backend, such as
     * "https://autopush.zinc.cloud.cupronickel.goog:443/auth".
     *
     * <p>If this is not set, it will default to a reasonable Zinc server address.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
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
    public Builder setZincServiceType(String type) {
      if (!isNullOrEmpty(type)) {
        this.zincServiceType = type;
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
    public Builder setConnectivityCheckRetryDelay(Duration retryDelay) {
      if (retryDelay != null) {
        this.connectivityCheckRetryDelay = retryDelay;
      }
      return this;
    }

    /**
     * Sets how many times to recheck whether a Network has internet connectivity, before assuming
     * it will not get internet without an intervening network event from Android.
     *
     * <p>If this is not set, it will default to a reasonable value.
     */
    public Builder setConnectivityCheckMaxRetries(int maxRetries) {
      this.connectivityCheckMaxRetries = maxRetries;
      return this;
    }

    /**
     * Sets the DNS address or v4/v6 address of the copper controller.
     *
     * <p>If null or an empty string is passed in, it will be ignored.
     */
    public Builder setCopperControllerAddress(String address) {
      if (!isNullOrEmpty(address)) {
        this.copperControllerAddress = Optional.of(address);
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

    /** Sets whether to use IPSec for the data path. */
    public Builder setIpSecEnabled(boolean ipSecEnabled) {
      this.ipSecEnabled = Optional.of(ipSecEnabled);
      return this;
    }

    /** Sets whether to use Bridge on PPN. */
    public Builder setBridgeOnPpnEnabled(boolean bridgeOnPpnEnabled) {
      this.bridgeOnPpnEnabled = Optional.of(bridgeOnPpnEnabled);
      return this;
    }

    /** Sets the key length to use for the bridge. */
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
    public Builder setRekeyDuration(Duration duration) {
      this.rekeyDuration = Optional.of(duration);
      return this;
    }

    public Builder setBlindSigningEnabled(boolean blindSigningEnabled) {
      this.blindSigningEnabled = Optional.of(blindSigningEnabled);
      return this;
    }

    /** Sets whether Krypton should install a signal handler to help gracefully handle crashes. */
    public Builder setShouldInstallKryptonCrashSignalHandler(boolean value) {
      this.shouldInstallKryptonCrashSignalHandler = Optional.of(value);
      return this;
    }

    /** Sets the initial time between reconnects. */
    public Builder setReconnectorInitialTimeToReconnect(Duration duration) {
      if (duration != null) {
        this.reconnectorInitialTimeToReconnect = Optional.of(duration);
      }
      return this;
    }

    /** Sets the deadline for a session to be established. */
    public Builder setReconnectorSessionConnectionDeadline(Duration duration) {
      if (duration != null) {
        this.reconnectorSessionConnectionDeadline = Optional.of(duration);
      }
      return this;
    }

    public Builder setStickyService(boolean isStickyService) {
      this.isStickyService = isStickyService;
      return this;
    }

    public Builder setSafeDisconnectEnabled(boolean enabled) {
      this.safeDisconnectEnabled = enabled;
      return this;
    }

    /** Sets the list of apps that will bypass the VPN, as package names. */
    public Builder setDisallowedApplications(Iterable<String> packageNames) {
      HashSet<String> copy = new HashSet<>();
      for (String packageName : packageNames) {
        copy.add(packageName);
      }
      this.disallowedApplications = Collections.unmodifiableSet(copy);
      return this;
    }

    /** Sets whether to use an internal DNS cache in the library. */
    public Builder setDnsCacheEnabled(boolean enabled) {
      this.dnsCacheEnabled = enabled;
      return this;
    }

    /** Sets the Executor that PPN should use for most work it needs to do in the background. */
    public Builder setBackgroundExecutor(ExecutorService executor) {
      this.backgroundExecutor = Optional.of(executor);
      return this;
    }

    public Builder setAccountManager(PpnAccountManager accountManager) {
      this.accountManager = Optional.of(accountManager);
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
}
