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
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnException;
import java.io.IOException;

/** An account manager for first-party apps. This uses GMSCore APIs to get look up Accounts. */
public class GoogleAccountManager implements PpnAccountManager {
  private static final String TAG = "PPN GoogleAccountManager";

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
  public String getOAuthToken(Context context, Account account, String scope) throws PpnException {
    // TODO: Perhaps add a mechanism for passing in a particular network.
    Bundle extras = new Bundle();
    try {
      return GoogleAuthUtil.getTokenWithNotification(context, account, scope, extras);
    } catch (IOException | GoogleAuthException e) {
      throw new PpnException("Unable to obtain oauth token.", e);
    }
  }
}
