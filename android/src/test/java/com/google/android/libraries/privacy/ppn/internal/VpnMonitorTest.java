// Copyright 2023 Google LLC
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

package com.google.android.libraries.privacy.ppn.internal;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.NetworkRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class VpnMonitorTest {
  @Rule public final MockitoRule mocks = MockitoJUnit.rule();

  @Mock private ConnectivityManager mockConnectivityManager;

  @Test
  public void start_startsNetworkRequest() throws Exception {
    VpnMonitor vpnMonitor = new VpnMonitor(mockConnectivityManager);

    vpnMonitor.start();

    verify(mockConnectivityManager)
        .registerNetworkCallback(any(NetworkRequest.class), any(NetworkCallback.class));
  }

  @Test
  public void start_secondStartIgnored() throws Exception {
    VpnMonitor vpnMonitor = new VpnMonitor(mockConnectivityManager);
    vpnMonitor.start();

    vpnMonitor.start();

    verify(mockConnectivityManager)
        .registerNetworkCallback(any(NetworkRequest.class), any(NetworkCallback.class));
  }

  @Test
  public void stop_stopsNetworkRequest() throws Exception {
    VpnMonitor vpnMonitor = new VpnMonitor(mockConnectivityManager);
    vpnMonitor.start();

    vpnMonitor.stop();

    verify(mockConnectivityManager).unregisterNetworkCallback(any(NetworkCallback.class));
  }
}
