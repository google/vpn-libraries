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

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import java.util.UUID;

/** TimerIdWorker is a Krypton Timer worker scheduled using WorkManager. */
public final class TimerIdWorker extends Worker {
  private static final String TAG = "TimerIdWorker";

  public TimerIdWorker(@NonNull Context context, @NonNull WorkerParameters params) {
    super(context, params);
  }

  @Override
  public Result doWork() {
    int timerId = getInputData().getInt(TimerIdTask.KEY_TIMER_ID, -1);
    UUID managerId = UUID.fromString(getInputData().getString(TimerIdTask.KEY_MANAGER_UUID));
    TimerIdManager timerIdManager = TimerIdManager.getInstance(managerId);
    if (timerIdManager == null) {
      Log.w(
          TAG, "TimerIdWorker " + timerId + " expired for nonexistent TimerIdManager " + managerId);
      return Result.failure();
    }
    Log.w(TAG, "Timer worker " + timerId + " calling onTimerExpired.");
    timerIdManager.onTimerExpired(timerId);
    return Result.success();
  }
}
