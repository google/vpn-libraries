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


package com.google.android.libraries.privacy.ppn.internal;

import static com.google.common.truth.Truth.assertThat;

import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link PpnSettings}. */
@RunWith(RobolectricTestRunner.class)
public class PpnSettingsTest {

  private final PpnSettings ppnSettings =
      new PpnSettings(ApplicationProvider.getApplicationContext());

  @Test
  public void setAccountName_storesName() {
    String username = "Someuser@test.com";
    assertThat(ppnSettings.getAccountName()).isNull();

    ppnSettings.setAccountName(username);

    assertThat(ppnSettings.getAccountName()).isEqualTo(username);
  }

  @Test
  public void removeAccount_clearsName() {
    String username = "Someuser@test.com";
    ppnSettings.setAccountName(username);
    assertThat(ppnSettings.getAccountName()).isEqualTo(username);

    ppnSettings.removeAccountName();

    assertThat(ppnSettings.getAccountName()).isNull();
  }
}
