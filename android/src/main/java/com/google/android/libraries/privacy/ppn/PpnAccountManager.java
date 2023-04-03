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

import android.accounts.Account;
import android.content.Context;
import android.net.Network;
import androidx.annotation.Nullable;

/**
 * Common interface for getting account information, since the particular implementation may differ
 * between first-party and third-party apps.
 */
public interface PpnAccountManager {
  /**
   * Returns the Account with the given name.
   *
   * @throws PpnException if the account is not signed in.
   */
  Account getAccount(Context context, String accountName) throws PpnException;

  /**
   * Returns an oauth token for the given Account and scope.
   *
   * @throws PpnException if the app doesn't have permission for the given scope.
   */
  String getOAuthToken(Context context, Account account, String scope, @Nullable Network network)
      throws PpnException;
}
