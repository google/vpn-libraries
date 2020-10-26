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

package com.google.android.libraries.privacy.ppn.xenon.impl;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus.ConnectionQuality;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkSelector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * PpnNetworkSelector Implementation.
 *
 * <ul>
 *   It is responsible for:
 *   <li>choosing the best Network to use according to a strategy.
 *   <li>providing util methods for determining how good a Network is.
 */
final class PpnNetworkSelectorImpl implements PpnNetworkSelector {
  private static final String TAG = "PpnNetworkSelectorImpl";

  private final Context context;

  /**
   * Default Comparator that sorts Wifi Networks ahead of Cellular ones. If both networks are of the
   * same type, we order the preference by latest creation timestamp -- we want the newest network
   * in the list.
   *
   * <p>TODO: Consider handling the case where PpnNetworkType is Unknown.
   */
  private final Comparator<PpnNetwork> defaultNetworkComparator =
      Comparator.<PpnNetwork>comparingInt((ppnNetwork) -> ppnNetwork.getNetworkType().getNumber())
          // We want to order later networks first -- hence the -1 multiplier to inverse the
          // timestamps
          .thenComparingLong((ppnNetwork) -> ppnNetwork.getCreationTimestamp() * -1);

  public PpnNetworkSelectorImpl(Context context) {
    this.context = context;
  }

  @Override
  public PpnNetwork getBestNetwork(List<PpnNetwork> ppnNetworkList) {
    if (ppnNetworkList.isEmpty()) {
      return null;
    }
    return defaultPriorityStrategy(ppnNetworkList);
  }

  /**
   * The default network strategy.
   *
   * <p>This strategy always prioritize Wifi Networks over Cellular ones. If there is a tie (ie 2
   * Wifi Networks), it will pick the first one.
   *
   * <p>This method does NOT modify the passed in PpnNetwork List.
   */
  private PpnNetwork defaultPriorityStrategy(List<PpnNetwork> ppnNetworkList) {
    List<PpnNetwork> ppnNetworkListCopy = new ArrayList<>(ppnNetworkList);

    Collections.sort(ppnNetworkListCopy, defaultNetworkComparator);
    return ppnNetworkListCopy.get(0);
  }

  @Override
  public ConnectionQuality getConnectionQuality(PpnNetwork ppnNetwork, int rssi) {
    // If the RSSI is explicitly set, use it. Otherwise, we get the RSSI from the Wifi/Cellular
    // Manager depending on the NetworkType.
    if (rssi != 0) {
      return getConnectionQuality(ppnNetwork.getNetworkType(), rssi);
    }

    if (ppnNetwork.getNetworkType() == NetworkType.WIFI) {
      WifiManager wifiManager = getWifiManager();
      WifiInfo wifiInfo = wifiManager.getConnectionInfo();

      return getWifiConnectionQuality(wifiInfo.getRssi());
    }

    // We currently do NOT support getting the cellular signal from the CellularManager
    // TODO: Get the RSSI for the cellular signal.
    return ConnectionQuality.UNKNOWN_QUALITY;
  }

  private static ConnectionQuality getConnectionQuality(
      NetworkType networkType, int rssiSignalStrength) {
    if (networkType == NetworkType.WIFI) {
      return getWifiConnectionQuality(rssiSignalStrength);
    }
    if (networkType == NetworkType.CELLULAR) {
      return getCellularConnectionQuality(rssiSignalStrength);
    }

    return ConnectionQuality.UNKNOWN_QUALITY;
  }

  // Method for getting the Wifi ConnectionQuality according to
  // https://www.metageek.com/training/resources/understanding-rssi.html
  private static ConnectionQuality getWifiConnectionQuality(int rssiSignalStrength) {
    if (rssiSignalStrength >= -40) {
      return ConnectionQuality.EXCELLENT;
    } else if (rssiSignalStrength >= -67) {
      return ConnectionQuality.GOOD;
    } else if (rssiSignalStrength >= -70) {
      return ConnectionQuality.FAIR;
    } else if (rssiSignalStrength <= -71) {
      return ConnectionQuality.POOR;
    }

    return ConnectionQuality.UNKNOWN_QUALITY;
  }

  // Method for getting the Cellular ConnectionQuality according to
  // https://wiki.teltonika-networks.com/view/Mobile_Signal_Strength_Recommendations
  // We currently default to LTE mobile connection.
  private static ConnectionQuality getCellularConnectionQuality(int rssiSignalStrength) {
    if (rssiSignalStrength >= -65) {
      return ConnectionQuality.EXCELLENT;
    } else if (rssiSignalStrength >= -75) {
      return ConnectionQuality.GOOD;
    } else if (rssiSignalStrength >= -85) {
      return ConnectionQuality.FAIR;
    } else if (rssiSignalStrength <= -86) {
      return ConnectionQuality.POOR;
    }

    return ConnectionQuality.UNKNOWN_QUALITY;
  }

  private WifiManager getWifiManager() {
    return (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
  }
}
