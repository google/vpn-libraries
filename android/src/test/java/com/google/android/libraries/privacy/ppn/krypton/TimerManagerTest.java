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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.robolectric.Shadows.shadowOf;

import android.os.ConditionVariable;
import android.os.Looper;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.WorkManager;
import androidx.work.testing.WorkManagerTestInitHelper;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(AndroidJUnit4.class)
public final class TimerManagerTest {
  private static final String TAG = "TimerManagerTest";
  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  @Mock private TimerListener timerExpiryListener;
  private TimerIdManager timerIdManager;

  @Before
  public void setUp() {
    WorkManagerTestInitHelper.initializeTestWorkManager(
        ApplicationProvider.getApplicationContext());
    timerIdManager =
        new TimerIdManager(
            timerExpiryListener,
            (WorkManager)
                WorkManagerTestInitHelper.getTestDriver(
                    ApplicationProvider.getApplicationContext()));
  }

  @Test
  public void timerManagerStartAndExpiry_expectOnExpiry() throws Exception {
    // Set up a timer.
    final ConditionVariable condition = new ConditionVariable(false);
    doAnswer(
            invocation -> {
              condition.open();
              return null;
            })
        .when(timerExpiryListener)
        .onTimerExpired(1);

    // Start the timer to expire in 10ms.
    assertThat(timerIdManager.startTimer(1, 10)).isTrue();

    // Let the Looper run everything that will be ready in the next 15ms.
    shadowOf(Looper.getMainLooper()).idleFor(15, TimeUnit.MILLISECONDS);

    // Assert that the timer got run.
    assertThat(condition.block(1000)).isTrue();
  }

  @Test
  public void timerManagerStartAndCancel_expectTrueCancellation() throws Exception {
    assertThat(timerIdManager.startTimer(1, 1000)).isTrue();
    TimerIdTask task = timerIdManager.getTask(1);
    assertThat(timerIdManager.cancelTimer(1)).isTrue();
    // Verify that the manager called cancel on the task.
    assertThat(task.isCancelled()).isTrue();
    // Cancelling second time will result in error.
    assertThat(timerIdManager.cancelTimer(1)).isFalse();
    shadowOf(Looper.getMainLooper()).idle();
  }

  @Test
  public void timerManagerCancelAllTimers_expectAllCancellations() throws Exception {
    HashMap<Integer, TimerIdTask> tasks = new HashMap<>();
    for (int i = 0; i < 100; i++) {
      assertThat(timerIdManager.startTimer(i, 1000)).isTrue();
      tasks.put(i, timerIdManager.getTask(i));
    }
    assertThat(timerIdManager.size()).isEqualTo(100);
    timerIdManager.cancelAllTimers();
    assertThat(timerIdManager.size()).isEqualTo(0);
    for (Map.Entry<Integer, TimerIdTask> entry : tasks.entrySet()) {
      assertThat(entry.getValue().isCancelled()).isTrue();
    }
  }

  @Test
  public void timerManagerGetInstance_returnsCorrectManager() throws Exception {
    assertThat(TimerIdManager.getInstance(timerIdManager.getId())).isEqualTo(timerIdManager);
  }

  @Test
  public void timerManagerStop_removesManagerFromActiveManagers() throws Exception {
    UUID managerId = timerIdManager.getId();
    timerIdManager.stop();
    assertThat(TimerIdManager.getInstance(managerId)).isNull();
  }

  @Test
  public void timerManagerStop_cancelsRunningTimers() throws Exception {
    HashMap<Integer, TimerIdTask> tasks = new HashMap<>();
    for (int i = 0; i < 10; i++) {
      assertThat(timerIdManager.startTimer(i, 1000)).isTrue();
      tasks.put(i, timerIdManager.getTask(i));
    }
    assertThat(timerIdManager.size()).isEqualTo(10);
    timerIdManager.stop();
    assertThat(timerIdManager.size()).isEqualTo(0);
    for (Map.Entry<Integer, TimerIdTask> entry : tasks.entrySet()) {
      assertThat(entry.getValue().isCancelled()).isTrue();
    }
  }
}
