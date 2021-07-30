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

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Log;
import androidx.work.ListenableWorker;
import androidx.work.WorkerParameters;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

/** Refreshes OAuth token in device cache. */
public final class GoogleAccountRefreshWorker extends ListenableWorker {
  private static final String TAG = "GoogleAccountRefreshWorker";

  private final Context context;

  public GoogleAccountRefreshWorker(@NonNull Context context, @NonNull WorkerParameters params) {
    super(context, params);
    this.context = context;
  }

  @Override
  public ListenableFuture<Result> startWork() {
    SettableFuture<Result> future = SettableFuture.create();

    GoogleAccountRefresher refresher = GoogleAccountRefresher.getInstance();
    if (refresher == null) {
      Log.w(TAG, "GoogleAccountRefresher does not appear to be running.");
      future.set(Result.failure());
      return future;
    }

    refresher
        .fetchTokenAsync(context.getApplicationContext(), null)
        .continueWith(
            task -> {
              if (task.isSuccessful()) {
                future.set(Result.success());
              } else {
                Log.e(TAG, "Unable to fetch new oauth token.", task.getException());
                future.set(Result.failure());
              }
              return null;
            });

    return future;
  }
}
