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

import static java.util.concurrent.TimeUnit.SECONDS;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.content.Context;
import android.content.Intent;
import android.net.Network;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;

/** An account manager for first-party apps. This uses GMSCore APIs to get look up Accounts. */
public class OAuthAccountManager implements PpnAccountManager {
  private static final String TAG = "OAuthAccountManager";

  @Override
  public Account getAccount(Context context, String accountName) throws PpnException {
    AccountManager accountManager = AccountManager.get(context);
    Account[] accounts = accountManager.getAccounts();
    for (Account account : accounts) {
      if (account.name.equals(accountName)) {
        return account;
      }
    }
    throw new PpnException("Unable to retrieve account: " + accountName);
  }

  @Override
  public String getOAuthToken(
      Context context, Account account, String scope, @Nullable Network network)
      throws PpnException {
    Bundle bundle = getOAuthBundle(context, account, scope);

    String token = bundle.getString(AccountManager.KEY_AUTHTOKEN);
    if (token == null) {
      throw new PpnException("Unable to fetch OAuth token.");
    }
    return token;
  }

  private Bundle getOAuthBundle(Context context, Account account, String scope)
      throws PpnException {
    if (Looper.getMainLooper() == Looper.myLooper()) {
      throw new PpnException("Cannot fetch OAuth token async on main thread.");
    }

    TaskCompletionSource<Bundle> tcs = new TaskCompletionSource<>();

    AccountManager accountManager = AccountManager.get(context);
    Bundle options = new Bundle();

    accountManager.getAuthToken(
        account,
        scope,
        options,
        /*activity=*/ null,
        new AccountManagerCallback<Bundle>() {
          @Override
          public void run(AccountManagerFuture<Bundle> result) {
            try {
              Bundle bundle = result.getResult();
              tcs.trySetResult(bundle);
            } catch (Exception e) {
              Log.e(TAG, "Failed to fetch OAuth token.", e);
              tcs.trySetException(e);
            }
          }
        },
        null);

    try {
      return Tasks.await(tcs.getTask(), 30, SECONDS);
    } catch (Exception e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      Log.e(TAG, "Unable to fetch OAuth token.", e);
      throw new PpnException("Unable to fetch OAuth token.", e);
    }
  }

  @Override
  public void clearOAuthToken(Context context, String token) {}

  /**
   * Checks whether the user has already granted OAuth permissions.
   *
   * @return an Intent to get permission, or null if permission was already granted.
   */
  public Intent verifyAccountPermissions(Context context, Account account, String scope)
      throws PpnException {
    Bundle bundle = getOAuthBundle(context, account, scope);
    return bundle.getParcelable(AccountManager.KEY_INTENT);
  }
}
