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

import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus.ConnectionQuality;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONObject;

/** Utility class for creating and using Xenon debug json. */
public class XenonDebugJson {
  private XenonDebugJson() {}

  // Per-network keys.
  public static final String NETWORK_NAME = "networkName";
  public static final String NETWORK_TYPE = "networkType";

  public static final String AVAILABLE_NETWORKS = "availableNetworks";
  public static final String ACTIVE_NETWORK = "activeNetwork";
  public static final String PENDING_NETWORKS = "pendingNetworks";

  public static final String CONNECTION_QUALITY = "connectionQuality";

  /** Convenience builder for creating making the json. */
  public static class Builder {
    private final JSONObject json = new JSONObject();
    private final ArrayList<JSONObject> availableNetworks = new ArrayList<>();
    private final ArrayList<JSONObject> pendingNetworks = new ArrayList<>();

    @CanIgnoreReturnValue
    public Builder setActiveNetwork(PpnNetwork network) {
      Json.put(json, ACTIVE_NETWORK, encodeNetwork(network));
      return this;
    }

    @CanIgnoreReturnValue
    public Builder addAvailableNetwork(PpnNetwork network) {
      availableNetworks.add(encodeNetwork(network));
      return this;
    }

    @CanIgnoreReturnValue
    public Builder addPendingNetwork(PpnNetwork network) {
      pendingNetworks.add(encodeNetwork(network));
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setConnectionQuality(ConnectionQuality quality) {
      Json.put(json, CONNECTION_QUALITY, quality.name());
      return this;
    }

    public JSONObject build() {
      if (!availableNetworks.isEmpty()) {
        Json.put(json, AVAILABLE_NETWORKS, new JSONArray(availableNetworks));
      }
      if (!pendingNetworks.isEmpty()) {
        Json.put(json, PENDING_NETWORKS, new JSONArray(pendingNetworks));
      }
      return json;
    }

    private static JSONObject encodeNetwork(PpnNetwork network) {
      JSONObject json = new JSONObject();
      Json.put(json, NETWORK_NAME, network.getNetwork().toString());
      Json.put(json, NETWORK_TYPE, network.getNetworkType().name());
      return json;
    }
  }
}
