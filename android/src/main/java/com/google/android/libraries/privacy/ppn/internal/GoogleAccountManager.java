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

import android.accounts.Account;
import android.content.Context;
import android.net.Network;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.work.ListenableWorker;
import androidx.work.WorkManager;
import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.auth.TokenData;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnAccountRefresher;
import com.google.android.libraries.privacy.ppn.PpnException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executor;

/** An account manager for first-party apps. This uses GMSCore APIs to get look up Accounts. */
public class GoogleAccountManager implements PpnAccountManager {
  private static final String TAG = "GoogleAccountManager";

  @Override
  public PpnAccountRefresher createAccountRefresher(
      WorkManager workManager, Executor backgroundExecutor, String accountName, String scope) {
    return new GoogleAccountRefresher(workManager, this, backgroundExecutor, accountName, scope);
  }

  @Override
  public Account getAccount(Context context, String accountName) throws PpnException {
    try {
      Account[] accounts = GoogleAuthUtil.getAccounts(context, GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
      for (Account account : accounts) {
        if (account.name.equals(accountName)) {
          return account;
        }
      }
    } catch (RemoteException
        | GooglePlayServicesRepairableException
        | GooglePlayServicesNotAvailableException e) {
      // This method is used by the PPN Service to recreate the user account that enabled PPN in a
      // previous session. It's not used in an interactive context, so it can't be recoverable.
      throw new PpnException("Unable to retrieve account: " + accountName, e);
    }
    // The user is no longer available to the app.
    throw new PpnException("Unable to retrieve account: " + accountName);
  }

  @Override
  public PpnTokenData getOAuthToken(
      Context context, Account account, String scope, @Nullable Network network)
      throws PpnException {
    Bundle extras = new Bundle();
    if (network != null) {
      extras.putParcelable(GoogleAuthUtil.KEY_NETWORK_TO_USE, network);
    }
    try {
      TokenData tokenData =
          GoogleAuthUtil.getTokenWithDetailsAndNotification(context, account, scope, extras);
      Long expirationTimeSecs = tokenData.getExpirationTimeSecs();
      Instant expiration;
      if (expirationTimeSecs != null) {
        expiration = Instant.ofEpochSecond(tokenData.getExpirationTimeSecs());
        Duration expiresIn = Duration.between(Instant.now(), expiration);
        Log.w(TAG, "OAuth token expires in " + expiresIn + " at " + expiration);
      } else {
        // It's not clear why gmscore sometimes gives us null expiration times, but we should assume
        // the timeout is long enough that PPN should try to use the token, but short enough that
        // next time it needs one, it tries to fetch again.
        expiration = Instant.now().plusSeconds(60);
        Log.w(TAG, "OAuth token has null expiration time. Assuming it expires in 1 minute.");
      }
      return new PpnTokenData(tokenData.getToken(), expiration);
    } catch (IOException | GoogleAuthException e) {
      throw new PpnException("Unable to obtain oauth token.", e);
    }
  }

  @Override
  public Class<? extends ListenableWorker> getWorkerClass() {
    return GoogleAccountRefreshWorker.class;
  }
}
