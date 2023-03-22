/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.libraries.privacy.ppn.neon;

import static android.net.ipsec.ike.SaProposal.DH_GROUP_4096_BIT_MODP;
import static android.net.ipsec.ike.SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16;
import static android.net.ipsec.ike.SaProposal.KEY_LEN_AES_256;
import static android.net.ipsec.ike.SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC;

import android.accounts.Account;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Notification;
import android.content.Context;
import android.net.Ikev2VpnProfile;
import android.net.VpnManager;
import android.net.ipsec.ike.ChildSaProposal;
import android.net.ipsec.ike.IkeKeyIdIdentification;
import android.net.ipsec.ike.IkeSaProposal;
import android.net.ipsec.ike.IkeSessionParams;
import android.net.ipsec.ike.IkeTunnelConnectionParams;
import android.net.ipsec.ike.TunnelModeChildSessionParams;
import android.system.OsConstants;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.IpGeoLevel;
import com.google.android.libraries.privacy.ppn.Ppn;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnListener;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnTelemetry;
import com.google.android.libraries.privacy.ppn.internal.AccountCache;
import com.google.android.libraries.privacy.ppn.internal.GoogleAccountManager;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.krypton.AttestingOAuthTokenProvider;
import com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider;
import com.google.android.libraries.privacy.ppn.proto.PpnIkeResponse;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import org.json.JSONObject;

/** An implementation of PPN that uses IKE+VpnManager, instead of VpnService. */
@TargetApi(32)
public class IkePpnImpl implements Ppn, Provision.Listener {
  private static final String TAG = "IkePpnImpl";

  private final Context context;
  private final HttpFetcher httpFetcher;
  private final OAuthTokenProvider tokenProvider;
  private final Provision provision;
  private final PpnAccountManager accountManager;
  private final AccountCache accountCache;
  private final ExecutorService backgroundExecutor;
  private final PpnOptions options;
  private final VpnManager vpnManager;

  public IkePpnImpl(Context context, PpnOptions options) {
    this.context = context.getApplicationContext();
    this.options = options;
    httpFetcher = new HttpFetcher(new ProvisionSocketFactoryFactory());
    backgroundExecutor = options.getBackgroundExecutor();
    vpnManager = (VpnManager) context.getSystemService(Context.VPN_MANAGEMENT_SERVICE);

    this.accountManager = options.getAccountManager().orElseGet(GoogleAccountManager::new);
    this.accountCache = new AccountCache(context, backgroundExecutor, accountManager);

    if (options.isIntegrityAttestationEnabled()) {
      tokenProvider =
          new AttestingOAuthTokenProvider(context, options) {
            @Override
            public String getOAuthToken() {
              try {
                return IkePpnImpl.this.getOAuthToken();
              } catch (PpnException e) {
                Log.e(TAG, "Unable to get account.", e);
                // Return empty string, because this is called by JNI.
                return "";
              }
            }
          };
    } else {
      tokenProvider =
          new OAuthTokenProvider() {
            @Override
            public String getOAuthToken() {
              try {
                return IkePpnImpl.this.getOAuthToken();
              } catch (PpnException e) {
                Log.e(TAG, "Unable to get account.", e);
                return "";
              }
            }

            @Override
            @Nullable
            public byte[] getAttestationData(String nonce) {
              return null;
            }
          };
    }

    // TODO: Either change the factory to throw or refactor this to not throw here.
    Provision p = null;
    try {
      p = new Provision(options, httpFetcher, tokenProvider, this);
    } catch (PpnException e) {
      Log.e(TAG, "Unable to create provision.", e);
    }
    provision = p;
  }

  private String getOAuthToken() throws PpnException {
    Account account = accountCache.getPpnAccount();
    return accountManager.getOAuthToken(context, account, options.getZincOAuthScopes(), null);
  }

  private Ikev2VpnProfile buildVpnProfile(PpnIkeResponse ikeResponse) {
    byte[] clientId = ikeResponse.getClientId().toByteArray();
    final IkeSaProposal ikeProposal =
        new IkeSaProposal.Builder()
            .addEncryptionAlgorithm(ENCRYPTION_ALGORITHM_AES_GCM_16, KEY_LEN_AES_256)
            .addDhGroup(DH_GROUP_4096_BIT_MODP)
            .addPseudorandomFunction(PSEUDORANDOM_FUNCTION_AES128_XCBC)
            .build();
    // Without this line, the IKE_OPTION_FORCE_PORT_4500 won't compile without --norun_validations.
    @SuppressLint("WrongConstant")
    final IkeSessionParams ikeParams =
        new IkeSessionParams.Builder()
            .setServerHostname(ikeResponse.getServerAddress())
            .setLocalIdentification(new IkeKeyIdIdentification(clientId))
            // TODO: Move this into PpnOptions.
            .setRemoteIdentification(new IkeKeyIdIdentification("wormhole-server".getBytes()))
            .setAuthPsk(ikeResponse.getSharedSecret().toByteArray())
            .addIkeSaProposal(ikeProposal)
            .addIkeOption(IkeSessionParams.IKE_OPTION_MOBIKE)
            .addIkeOption(IkeSessionParams.IKE_OPTION_FORCE_PORT_4500)
            .build();

    final ChildSaProposal childProposal =
        new ChildSaProposal.Builder()
            .addEncryptionAlgorithm(ENCRYPTION_ALGORITHM_AES_GCM_16, KEY_LEN_AES_256)
            .build();
    final TunnelModeChildSessionParams childParams =
        new TunnelModeChildSessionParams.Builder()
            .addChildSaProposal(childProposal)
            .addInternalAddressRequest(OsConstants.AF_INET)
            .addInternalAddressRequest(OsConstants.AF_INET6)
            .addInternalDnsServerRequest(OsConstants.AF_INET)
            .addInternalDnsServerRequest(OsConstants.AF_INET6)
            .build();

    // TODO: Double check these params.
    return new Ikev2VpnProfile.Builder(new IkeTunnelConnectionParams(ikeParams, childParams))
        .setMaxMtu(1280)
        .setMetered(false)
        .setBypassable(true)
        .setLocalRoutesExcluded(true)
        .build();
  }

  private void setUpIke(PpnIkeResponse ikeResponse) {
    Ikev2VpnProfile profile = buildVpnProfile(ikeResponse);
    if (vpnManager.provisionVpnProfile(profile) != null) {
      Log.e(TAG, "provisionVpnProfile returned a non-null Intent.");
    }
    vpnManager.startProvisionedVpnProfileSession();
  }

  @Override
  public void start(Account account) throws PpnException {
    Log.i(TAG, "Starting ppn.");
    accountCache.setAccount(account);
    provision.start();
  }

  @Override
  public void stop() {
    Log.i(TAG, "Stopping ppn.");
    vpnManager.stopProvisionedVpnProfile();
  }

  @Override
  public ListenableFuture<Void> restart() {
    Log.i(TAG, "Restarting ppn.");
    return Futures.immediateVoidFuture();
  }

  @Override
  public ListenableFuture<Void> snooze(Duration snoozeDuration) {
    Log.i(TAG, "Snoozing for " + snoozeDuration);
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public ListenableFuture<Void> resume() {
    Log.i(TAG, "Resuming from snooze.");
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public ListenableFuture<Void> extendSnooze(Duration extendDuration) {
    Log.i(TAG, "Extending snooze by " + extendDuration);
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public ListenableFuture<Void> setSafeDisconnectEnabled(boolean enable) {
    Log.i(TAG, "Setting safe disconnect to " + enable);
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public ListenableFuture<Void> setIpGeoLevel(IpGeoLevel level) {
    Log.i(TAG, "Setting ip geo level to " + level);
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public void setDisallowedApplications(Iterable<String> disallowedApplications) {
    Log.i(TAG, "Setting disallowed applications.");
  }

  @Override
  public boolean isSafeDisconnectEnabled() {
    return false;
  }

  @Override
  public void setPpnListener(PpnListener listener) {
    Log.i(TAG, "Setting PpnListener.");
  }

  @Override
  public PpnTelemetry collectTelemetry() {
    Log.i(TAG, "Collecting telemetry.");
    return PpnTelemetry.builder().build();
  }

  @Override
  public boolean isRunning() {
    return false;
  }

  @Override
  public void setNotification(int notificationId, Notification notification) {
    Log.i(TAG, "Setting PPN notification.");
  }

  @Override
  public ListenableFuture<Void> setSimulatedNetworkFailure(boolean simulatedNetworkFailure) {
    // This cannot be implemented with VpnManager, because PPN doesn't control the dataplane.
    return Futures.immediateFailedFuture(new IllegalStateException("not implemented"));
  }

  @Override
  public JSONObject getDebugJson() {
    return new JSONObject();
  }

  @Override
  public void onProvisioned(PpnIkeResponse ikeResponse) {
    Log.i(TAG, "Provisioned.");
    setUpIke(ikeResponse);
  }

  @Override
  public void onProvisioningFailure(PpnStatus status, boolean permanent) {
    Log.e(TAG, "Provisioning failed: " + status.getCode() + ": " + status.getMessage());
  }
}
