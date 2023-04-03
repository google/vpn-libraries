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

package com.google.android.libraries.privacy.ppn.xenon.impl;

import android.content.Context;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkManager;
import com.google.android.libraries.privacy.ppn.xenon.Xenon;
import java.util.List;
import org.json.JSONObject;

/** Basic Xenon Implementation that will be used by PpnImpl. */
public final class XenonImpl implements Xenon {
  private final PpnNetworkManager ppnNetworkManager;

  public XenonImpl(
      Context context,
      PpnNetworkListener listener,
      HttpFetcher httpFetcher,
      PpnOptions ppnOptions) {
    this.ppnNetworkManager = new PpnNetworkManagerImpl(context, listener, httpFetcher, ppnOptions);
  }

  @Override
  public void start() {
    this.ppnNetworkManager.startNetworkRequests();
  }

  @Override
  public void stop() {
    this.ppnNetworkManager.stopNetworkRequests();
  }

  @Override
  @Nullable
  public PpnNetwork getNetwork(long id) {
    return this.ppnNetworkManager.getPpnNetwork(id);
  }

  @Override
  public boolean deprioritize(NetworkInfo networkInfo) {
    return this.ppnNetworkManager.deprioritize(networkInfo);
  }

  @Override
  public void reevaluateNetworks() {
    this.ppnNetworkManager.reevaluateNetworks();
  }

  @Override
  public List<PpnNetwork> getAvailableNetworks() {
    return this.ppnNetworkManager.getAllNetworks();
  }

  @Override
  public JSONObject getDebugJson() {
    return this.ppnNetworkManager.getDebugJson();
  }
}
