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

package com.google.android.libraries.privacy.ppn.krypton;

import android.os.Handler;
import android.util.Log;
import androidx.work.Data;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import com.google.common.annotations.VisibleForTesting;
import java.time.Duration;
import java.util.UUID;

/**
 * TimerIdTask represents a single Krypton Timer, wrapping a TimerIdRunnable (android.os.Handler)
 * and a TimerIdWorker (androidx.work.WorkManager).
 */
public class TimerIdTask {
  private final Handler handler;
  private final WorkManager workManager;
  private final UUID managerId;
  private final int timerId;
  private final Duration delay;

  private final OneTimeWorkRequest workRequest;
  private final TimerIdRunnable runnable;

  public static final String TAG = "TimerIdTask";
  public static final String KEY_TIMER_ID = "timerId";
  public static final String KEY_MANAGER_UUID = "managerId";

  // For testing purposes.
  private boolean isCancelled;

  public TimerIdTask(
      TimerIdListener listener,
      UUID managerId,
      Handler handler,
      WorkManager workManager,
      int timerId,
      Duration delay) {
    this.handler = handler;
    this.workManager = workManager;
    this.managerId = managerId;
    this.timerId = timerId;
    this.delay = delay;
    this.isCancelled = false;

    this.runnable = new TimerIdRunnable(listener, timerId);
    this.workRequest = createOneTimeWorkRequest();
  }

  public void start() {
    if (!handler.postDelayed(runnable, delay.toMillis())) {
      throw new IllegalStateException("postDelayed returned false.");
    }
    workManager.enqueue(workRequest);
    Log.w(TAG, "Started TimerIdTask " + timerId + " with delay of " + delay);
  }

  public void cancel() {
    Log.w(TAG, "Canceling TimerIdTask " + timerId);
    handler.removeCallbacksAndMessages(runnable);
    workManager.cancelWorkById(workRequest.getId());
    isCancelled = true;
  }

  private OneTimeWorkRequest createOneTimeWorkRequest() {
    Data workerData =
        new Data.Builder()
            .putInt(KEY_TIMER_ID, timerId)
            .putString(KEY_MANAGER_UUID, managerId.toString())
            .build();
    return new OneTimeWorkRequest.Builder(TimerIdWorker.class)
        .setInitialDelay(delay)
        .setInputData(workerData)
        .build();
  }

  @VisibleForTesting
  boolean isCancelled() {
    return isCancelled;
  }
}
