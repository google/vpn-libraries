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

package com.google.android.libraries.privacy.ppn.xenon.impl.v2;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus.ConnectionQuality;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkSelector;
import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowNetwork;
import org.robolectric.shadows.ShadowWifiManager;

@RunWith(RobolectricTestRunner.class)
public final class PpnNetworkSelectorImplTest {
  private PpnNetworkSelector ppnNetworkSelector;
  private ShadowWifiManager shadowWifiManager;

  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  @Mock private WifiInfo mockWifiInfo;

  @Before
  public void setUp() {
    Context context = ApplicationProvider.getApplicationContext();
    shadowWifiManager = shadowOf(context.getSystemService(WifiManager.class));
    ppnNetworkSelector = new PpnNetworkSelectorImpl(context);
  }

  @Test
  public void testGetBestNetwork_emptyNetworkList() throws Exception {
    assertThat(ppnNetworkSelector.getBestNetwork(ImmutableList.of())).isEqualTo(null);
  }

  @Test
  public void testGetBestNetwork_defaultStrategy() throws Exception {
    ImmutableList<PpnNetwork> availableNetworks =
        ImmutableList.of(
            new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR),
            new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 2), NetworkType.WIFI));

    PpnNetwork bestNetwork = ppnNetworkSelector.getBestNetwork(availableNetworks);
    // We expect the Wifi network with netId 2 to be returned
    assertThat(shadowOf(bestNetwork.getNetwork()).getNetId()).isEqualTo(2);
    assertThat(bestNetwork.getNetworkType()).isEqualTo(NetworkType.WIFI);
  }

  @Test
  public void testGetBestNetwork_defaultStrategy_newerNetworks() throws Exception {
    PpnNetwork cellNetwork1 =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    PpnNetwork cellNetwork2 =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 2), NetworkType.CELLULAR);
    PpnNetwork cellNetwork3 =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 3), NetworkType.CELLULAR);
    PpnNetwork wifiNetwork4 =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 4), NetworkType.WIFI);
    PpnNetwork wifiNetwork5 =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 5), NetworkType.WIFI);

    ImmutableList<PpnNetwork> availableNetworks =
        ImmutableList.of(cellNetwork1, cellNetwork2, cellNetwork3, wifiNetwork4, wifiNetwork5);

    PpnNetwork bestNetwork = ppnNetworkSelector.getBestNetwork(availableNetworks);
    // We expect the Wifi network with netId 5 to be returned.
    assertThat(shadowOf(bestNetwork.getNetwork()).getNetId()).isEqualTo(5);
    assertThat(bestNetwork.getNetworkType()).isEqualTo(NetworkType.WIFI);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_wifiExcellent() throws Exception {
    // The RSSI db value of an Excellent Wifi Connection.
    int rssi = -10;

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.EXCELLENT);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_wifiGood() throws Exception {
    // The RSSI db value of a Good Wifi Connection.
    int rssi = -66;

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.GOOD);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_wifiFair() throws Exception {
    // The RSSI db value of a Fair Wifi Connection.
    int rssi = -69;

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.FAIR);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_wifiPoor() throws Exception {
    // The RSSI db value of a Poor Wifi Connection.
    int rssi = -79;

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.POOR);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_wifiPoor2() throws Exception {
    // The RSSI db value of a more Poor Wifi Connection.
    int rssi = -91;

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.POOR);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_cellularExcellent() throws Exception {
    // The RSSI db value of an Excellent Cellular Connection.
    int rssi = -64;

    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.EXCELLENT);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_cellularGood() throws Exception {
    // The RSSI db value of a Good Cellular Connection.
    int rssi = -74;

    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.GOOD);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_cellularFair() throws Exception {
    // The RSSI db value of a Fair Cellular Connection.
    int rssi = -84;

    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.FAIR);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_cellularPoor() throws Exception {
    // The RSSI db value of a Poor Cellular Connection.
    int rssi = -94;

    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.POOR);
  }

  @Test
  public void testGetConnectionQuality_overrideRssi_cellularPoor2() throws Exception {
    // The RSSI db value of a more Poor Cellular Connection.
    int rssi = -96;

    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, rssi);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.POOR);
  }

  @Test
  public void testGetConnectionQuality_noRssi_wifiManager() throws Exception {
    // The RSSI db value of a Fair Wifi Connection.
    int rssi = -70;

    // Mock the return of the RSSI getting it from the Android WifiManager.
    when(mockWifiInfo.getRssi()).thenReturn(rssi);
    shadowWifiManager.setConnectionInfo(mockWifiInfo);

    PpnNetwork wifiNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.WIFI);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(wifiNetwork, /* rssi= */ 0);
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.FAIR);
  }

  @Test
  public void testGetConnectionQuality_noRssi_cellularManager() throws Exception {
    PpnNetwork cellularNetwork =
        new PpnNetwork(ShadowNetwork.newInstance(/* netId= */ 1), NetworkType.CELLULAR);
    ConnectionQuality connectionQuality =
        ppnNetworkSelector.getConnectionQuality(cellularNetwork, /* rssi= */ 0);

    // We are returning UNKNOWN for Cellular Connections needing to lookup the RSSI
    assertThat(connectionQuality).isEqualTo(ConnectionQuality.UNKNOWN_QUALITY);
  }
}
