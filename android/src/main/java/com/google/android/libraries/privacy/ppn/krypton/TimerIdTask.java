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

import android.util.Log;

/** A single unit timer object that represents one timer. */
final class TimerIdTask implements Runnable {
  public static final String TAG = "TimerIdTask";
  private final int timerId;
  private final TimerIdListener listener;

  /**
   * @param listener is called with onTimerExpired
   * @param timerId id of the timer.
   */
  public TimerIdTask(TimerIdListener listener, int timerId) {
    this.timerId = timerId;
    this.listener = listener;
  }

  @Override
  public void run() {
    Log.w(TAG, "Timer Id " + timerId + " expired");
    // This signals the TimerIdManager that this timer is expired.
    listener.onTimerExpired(timerId);
  }
}
