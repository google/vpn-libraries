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

package com.google.android.libraries.privacy.ppn;

import static android.app.Service.START_NOT_STICKY;
import static android.app.Service.START_STICKY;
import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Intent;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.internal.PpnImpl;
import com.google.android.libraries.privacy.ppn.internal.PpnLibrary;
import com.google.testing.mockito.Mocks;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class PpnVpnServiceTest {

  @Rule public Mocks mocks = new Mocks(this);

  @Mock private PpnImpl ppn;
  private PpnVpnService ppnVpnService;

  @Before
  public void setup() {
    ppnVpnService = new PpnVpnService();
    PpnLibrary.init(ppn);
  }

  @After
  public void teardown() {
    PpnLibrary.clear();
  }

  @Test
  public void onCreate_startPpnService() {
    when(ppn.onStartService(any())).thenReturn(Tasks.forResult(null));

    ppnVpnService.onCreate();

    verify(ppn).onStartService(any());
  }

  @Test
  public void onDestroy_stopPpnService() {
    ppnVpnService.onDestroy();

    verify(ppn).onStopService();
  }

  @Test
  public void setStickyServiceTrue_shouldStartSticky() {
    when(ppn.isStickyService()).thenReturn(true);

    assertThat(ppnVpnService.onStartCommand(new Intent(), 0, 0)).isEqualTo(START_STICKY);
  }

  @Test
  public void setStickyServiceFalse_shouldStartNotSticky() {
    when(ppn.isStickyService()).thenReturn(false);

    assertThat(ppnVpnService.onStartCommand(new Intent(), 0, 0)).isEqualTo(START_NOT_STICKY);
  }

  @Test
  public void onRevoke_stopPpn() {
    ppnVpnService.onRevoke();

    verify(ppn).stop();
  }
}
