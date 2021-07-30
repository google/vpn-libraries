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

package com.google.android.libraries.privacy.ppn.krypton;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.work.WorkManager;
import com.google.common.annotations.VisibleForTesting;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** TimerManager for managing timers from Krypton. */
final class TimerIdManager implements TimerIdListener {
  public static final String TAG = "TimerIdManager";

  private final TimerListener listener;
  private final WorkManager workManager;
  // Each instance of TimerIdManager has a UUID.
  // WorkManager workers created by that TimerIdManager use the manager's UUID to get the instance.
  // If a timer returns for an inactive TimerIdManager, we can discard it based on UUID.
  private final UUID managerId;

  private static final ConcurrentHashMap<UUID, TimerIdManager> activeManagers =
      new ConcurrentHashMap<>();

  private final Handler handler = new Handler(Looper.getMainLooper());

  // Map to keep track of this manager's running timers.
  private final ConcurrentHashMap<Integer, TimerIdTask> runningTimers = new ConcurrentHashMap<>();

  static TimerIdManager getInstance(UUID uuid) {
    return activeManagers.get(uuid);
  }

  public TimerIdManager(TimerListener listener, WorkManager workManager) {
    this.listener = listener;
    this.workManager = workManager;
    this.managerId = UUID.randomUUID();
    activeManagers.put(managerId, this);
  }

  public void stop() {
    cancelAllTimers();
    activeManagers.remove(managerId);
  }

  @Override
  public void onTimerExpired(int timerId) {
    Log.w(TAG, "Timer expired for timerId " + timerId);
    TimerIdTask expiredTask = runningTimers.remove(timerId);
    if (expiredTask == null) {
      Log.w(
          TAG,
          "TimerId "
              + timerId
              + " has already been removed from runningTimers. It may be claimed by another"
              + " thread.");
      return;
    }
    expiredTask.cancel();
    // Pass the timer expiration onto the listener.
    listener.onTimerExpired(timerId);
  }

  /**
   * Start a timer for a given timer Id
   *
   * @param timerId ID for the timer, -1 is invalid. This should be a unique id and uniqueness is
   *     not validated by this class.
   * @param delayMilliseconds Milliseconds delay for the timer
   */
  public boolean startTimer(int timerId, int delayMilliseconds) {
    TimerIdTask timerIdTask =
        new TimerIdTask(
            this, managerId, handler, workManager, timerId, Duration.ofMillis(delayMilliseconds));
    try {
      // Use the task as its own cancellation token.
      timerIdTask.start();
      Log.w(TAG, "Started timer with id " + timerId + " for " + delayMilliseconds + "ms");
    } catch (IllegalStateException e) {
      runningTimers.remove(timerId);
      Log.w(TAG, "Could not start the timer with id " + timerId, e);
      return false;
    }
    runningTimers.put(timerId, timerIdTask);
    return true;
  }

  /**
   * Cancel a running timer
   *
   * @param timerId timerId that was used in startTimer that needs to be cancelled. Operation is
   *     NoOp if the timer is not running and returns false.
   */
  public boolean cancelTimer(int timerId) {
    TimerIdTask timerTask = runningTimers.remove(timerId);
    if (timerTask == null) {
      Log.w(TAG, "Timer with id " + timerId + " is not running.");
      return false;
    }
    timerTask.cancel();
    Log.w(TAG, "Timer with id " + timerId + " is cancelled.");
    return true;
  }

  /** Cancel all running timers. */
  public void cancelAllTimers() {
    Log.w(TAG, "Cancelling all timers");
    for (Map.Entry<Integer, TimerIdTask> entry : runningTimers.entrySet()) {
      entry.getValue().cancel();
    }
    runningTimers.clear();
  }

  /** returns the number of active timers */
  @VisibleForTesting
  public int size() {
    return runningTimers.size();
  }

  @VisibleForTesting
  public UUID getId() {
    return managerId;
  }

  @VisibleForTesting
  public TimerIdTask getTask(int timerId) {
    return runningTimers.get(timerId);
  }
}
