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
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.testing.mockito.Mocks;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;

@RunWith(AndroidJUnit4.class)
public final class TimerManagerTest {
  private static final String TAG = "TimerManagerTest";
  @Rule public Mocks mocks = new Mocks(this);
  @Mock private TimerListener timerExpiryListener;
  private TimerIdManager timerIdManager;

  @Before
  public void setUp() {
    timerIdManager = new TimerIdManager(timerExpiryListener);
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
    assertThat(timerIdManager.cancelTimer(1)).isTrue();
    // Cancelling second time will result in error.
    assertThat(timerIdManager.cancelTimer(1)).isFalse();
  }

  @Test
  public void timerManagerCancelAllTimers_expectAllCancellations() throws Exception {
    for (int i = 0; i < 100; i++) {
      assertThat(timerIdManager.startTimer(i, 1000)).isTrue();
    }
    assertThat(timerIdManager.size()).isEqualTo(100);
    timerIdManager.cancelAllTimers();
    assertThat(timerIdManager.size()).isEqualTo(0);
  }
}
