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
import com.google.common.annotations.VisibleForTesting;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** TimerManager for managing timers from Krypton. */
final class TimerIdManager implements TimerIdListener {

  public static final String TAG = "TimerIdManager";

  private final TimerListener listener;

  private final Handler handler = new Handler(Looper.getMainLooper());

  // Map to keep track of the running timers.
  private final ConcurrentHashMap<Integer, TimerIdTask> runningTimers = new ConcurrentHashMap<>();

  public TimerIdManager(TimerListener listener) {
    this.listener = listener;
  }

  @Override
  public void onTimerExpired(int timerId) {
    Log.w(TAG, "Timer expired for timerId " + timerId);
    runningTimers.remove(timerId);
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
    TimerIdTask timerIdTask = new TimerIdTask(this, timerId);
    try {
      // Use the task as its own cancellation token.
      if (!handler.postDelayed(timerIdTask, delayMilliseconds)) {
        throw new IllegalStateException("postDelayed returned false.");
      }
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
    TimerIdTask timerTask = runningTimers.get(timerId);
    if (timerTask == null) {
      Log.w(TAG, "Timer with id " + timerId + " is not running.");
      return false;
    }
    Log.w(TAG, "Timer with id " + timerId + " is cancelled.");
    runningTimers.remove(timerId);
    handler.removeCallbacks(timerTask);
    return true;
  }

  /** Cancel all running timers. */
  public void cancelAllTimers() {
    Log.w(TAG, "Cancelling all timers");
    for (Map.Entry<Integer, TimerIdTask> entry : runningTimers.entrySet()) {
      handler.removeCallbacksAndMessages(entry.getValue());
    }
    runningTimers.clear();
  }

  /** returns the number of active timers */
  @VisibleForTesting
  public int size() {
    return runningTimers.size();
  }
}
