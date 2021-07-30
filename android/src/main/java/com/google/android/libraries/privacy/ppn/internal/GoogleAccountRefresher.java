// Copyright 2021 Google LLC
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
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnAccountManager.PpnTokenData;
import com.google.android.libraries.privacy.ppn.PpnAccountRefresher;
import com.google.android.libraries.privacy.ppn.PpnException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/** GoogleAccountRefresher uses WorkManager to refresh the user's OAuth token every hour. */
public class GoogleAccountRefresher implements PpnAccountRefresher {
  private static final String TAG = "GoogleAccountRefresher";
  private static final String WORK_TAG = "refreshOAuthToken";
  private static final Duration REPEAT_INTERVAL = Duration.ofHours(1);

  // This class is effectively a singleton, since it uses a unique periodic worker.
  // This holds the reference to the current instance.
  private static final AtomicReference<GoogleAccountRefresher> instance = new AtomicReference<>();

  private final String accountName;
  private final String scope;
  private final PpnAccountManager accountManager;
  private final WorkManager workManager;
  private final Executor backgroundExecutor;

  private PpnTokenData tokenData;

  // A lock to make sure we don't call getToken multiple times simultaneously.
  private final Object getTokenLock = new Object();

  static GoogleAccountRefresher getInstance() {
    return instance.get();
  }

  public GoogleAccountRefresher(
      WorkManager workManager,
      PpnAccountManager accountManager,
      Executor backgroundExecutor,
      String accountName,
      String scope) {
    this.accountManager = accountManager;
    this.accountName = accountName;
    this.scope = scope;
    this.workManager = workManager;
    this.tokenData = null;
    this.backgroundExecutor = backgroundExecutor;
  }

  @Override
  public void start() {
    if (!instance.compareAndSet(null, this)) {
      throw new IllegalStateException("Only one GoogleAccountRefresher can run at a time.");
    }

    PeriodicWorkRequest currentWorkRequest = createPeriodicWorkRequest();
    workManager.enqueueUniquePeriodicWork(
        WORK_TAG, ExistingPeriodicWorkPolicy.REPLACE, currentWorkRequest);

    Log.w(TAG, "Started GoogleAccountRefresher with repeatInterval: " + REPEAT_INTERVAL);
  }

  @Override
  public void stop() {
    workManager.cancelUniqueWork(WORK_TAG);
    instance.set(null);
    Log.w(TAG, "Stopped GoogleAccountRefresher.");
  }

  @Override
  public String getToken(Context context, @Nullable Network network) throws PpnException {
    PpnTokenData currentToken = tokenData;
    Log.w(TAG, "There is a cached oauth token. Checking its expiration.");
    if (currentToken != null) {
      if (currentToken.getExpiration().isBefore(Instant.now())) {
        Log.w(TAG, "Token is expired. Clearing cache.");
        tokenData = null;
      } else {
        Log.w(TAG, "Using cached oauth token, which expires at " + currentToken.getExpiration());
        return currentToken.getToken();
      }
    }
    return fetchToken(context, network).getToken();
  }

  PpnTokenData fetchToken(Context context, @Nullable Network network) throws PpnException {
    Log.w(TAG, "Fetching new oauth token.");
    synchronized (getTokenLock) {
      Log.w(TAG, "Getting account for oauth token request.");
      Account account = accountManager.getAccount(context, accountName);
      Log.w(TAG, "Getting token data.");
      PpnTokenData tokenData = accountManager.getOAuthToken(context, account, scope, network);
      Log.w(TAG, "Got new oauth token, which expires at " + tokenData.getExpiration());
      try {
        GoogleAuthUtil.clearToken(context.getApplicationContext(), tokenData.getToken());
      } catch (GoogleAuthException | IOException e) {
        Log.w(TAG, "Unable to clear auth token.", e);
      }
      this.tokenData = tokenData;
      return tokenData;
    }
  }

  Task<PpnTokenData> fetchTokenAsync(Context context, @Nullable Network network) {
    Log.w(TAG, "Scheduling fetchToken on background Executor.");
    TaskCompletionSource<PpnTokenData> tcs = new TaskCompletionSource<>();
    backgroundExecutor.execute(
        () -> {
          Log.w(TAG, "Running fetchToken on background Executor.");
          try {
            tcs.setResult(fetchToken(context, network));
          } catch (Exception e) {
            tcs.setException(e);
          }
        });
    return tcs.getTask();
  }

  private PeriodicWorkRequest createPeriodicWorkRequest() {
    return new PeriodicWorkRequest.Builder(GoogleAccountRefreshWorker.class, REPEAT_INTERVAL)
        .build();
  }
}
