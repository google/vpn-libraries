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

package com.google.android.libraries.privacy.ppn.internal;

import android.accounts.Account;
import android.content.Context;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.common.base.Strings;
import java.util.concurrent.ExecutorService;

/**
 * Class to keep track of the user account last used with PPN, so that it can be reued when PPN is
 * started from the System Settings.
 */
public class AccountCache {
  private static final String TAG = "AccountCache";

  /*
   * Cached account that was used to enable PPN.
   * This is volatile because it is updated from a background thread.
   */
  private volatile Account cachedAccount = null;

  /* This field is null until it is needed, so that this can be constructed on the UI thread. */
  @Nullable private PpnSettings settings;
  private final Object settingsLock = new Object();

  private final Context applicationContext;
  private final ExecutorService backgroundExecutor;
  private final PpnAccountManager accountManager;

  public AccountCache(
      Context context, ExecutorService backgroundExecutor, PpnAccountManager accountManager) {
    this.applicationContext = context.getApplicationContext();
    this.backgroundExecutor = backgroundExecutor;
    this.accountManager = accountManager;
  }

  /** Clears the account cached in memory. */
  public void clearCachedAccount() {
    Log.i(TAG, "Clearing cached account.");
    cachedAccount = null;
  }

  /** Sets the account that will be used for PPN. */
  public void setAccount(Account account) {
    getSettings().setAccountName(account.name);
    cachedAccount = account;
  }

  private PpnSettings getSettings() {
    synchronized (settingsLock) {
      if (settings == null) {
        settings = new PpnSettings(applicationContext);
      }
      return settings;
    }
  }

  /**
   * Looks up the Account that was used to enable PPN.
   *
   * <p>If PPN has not been enabled with an account, then the return Task will be rejected with a
   * PpnException.
   *
   * @return a Task that will be resolved with the account.
   */
  public Task<Account> getPpnAccountAsync() {
    // If it's cached, just use that.
    if (cachedAccount != null) {
      return Tasks.forResult(cachedAccount);
    }

    // Do any remaining work off of the UI thread.
    TaskCompletionSource<Account> tcs = new TaskCompletionSource<>();
    backgroundExecutor.execute(
        () -> {
          try {
            tcs.trySetResult(getPpnAccount());
          } catch (Exception e) {
            tcs.trySetException(e);
          }
        });
    return tcs.getTask();
  }

  /**
   * Looks up the Account that was used to enable PPN. This should not be called from the UI thread.
   *
   * @throws PpnException if PPN has not been enabled with an account.
   */
  public Account getPpnAccount() throws PpnException {
    Log.w(TAG, "PPN getting Account.");
    ensureBackgroundThread();
    // Look up the Account used for starting PPN.
    String accountName = getSettings().getAccountName();
    if (Strings.isNullOrEmpty(accountName)) {
      throw new PpnException("PPN was started without a user account.");
    }
    Account account = accountManager.getAccount(applicationContext, accountName);
    Log.w(TAG, "PPN has Account.");
    cachedAccount = account;
    return account;
  }

  private static void ensureBackgroundThread() {
    if (Looper.getMainLooper().isCurrentThread()) {
      throw new IllegalStateException("Must not be called on the main thread.");
    }
  }
}
