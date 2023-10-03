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

package com.google.android.libraries.privacy.ppn;

import static android.os.Build.VERSION_CODES.O_MR1;
import static android.os.Build.VERSION_CODES.P;
import static com.google.common.truth.Truth.assertThat;

import com.google.android.libraries.privacy.ppn.internal.KryptonConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Unit tests for {@link PpnOptions}. */
@RunWith(RobolectricTestRunner.class)
public class PpnOptionsMinSdkTest {
  @Test
  @Config(sdk = O_MR1)
  public void createKryptonConfig_ipsecProtocolInPpnOptionsApiLevel27() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.IPSEC).build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    // The Android SDK being used does not support IpSecManager so it should default to Bridge.
    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.BRIDGE);
  }

  @Test
  @Config(sdk = P)
  public void createKryptonConfig_ipsecProtocolInPpnOptionsApiLevel28() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.IPSEC).build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    // The Android SDK being used supports IpSecManager so it should use IPsec.
    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.IPSEC);
  }

  @Test
  public void createKryptonConfig_bridgeProtocolInPpnOptions() {
    PpnOptions options =
        new PpnOptions.Builder().setDatapathProtocol(PpnOptions.DatapathProtocol.BRIDGE).build();

    KryptonConfig config = options.createKryptonConfigBuilder().build();

    assertThat(config.hasDatapathProtocol()).isTrue();
    assertThat(config.getDatapathProtocol()).isEqualTo(KryptonConfig.DatapathProtocol.BRIDGE);
  }
}
