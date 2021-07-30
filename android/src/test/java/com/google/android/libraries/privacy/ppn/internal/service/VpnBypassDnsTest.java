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

package com.google.android.libraries.privacy.ppn.internal.service;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import android.net.Network;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.http.Dns;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.testing.mockito.Mocks;
import java.net.InetAddress;
import java.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class VpnBypassDnsTest {
  @Rule public Mocks mocks = new Mocks(this);

  @Mock private VpnManager mockVpnManager;
  @Mock private Dns mockSystemDns;
  @Mock private Network mockNetwork;
  @Mock private InetAddress mockAddress;

  @Test
  public void lookup_usesFallbackWhenNoNetworkSet() throws Exception {
    String hostname = "foo.bar.baz";
    doReturn(null).when(mockVpnManager).getNetwork();
    doReturn(Arrays.asList(mockAddress)).when(mockSystemDns).lookup(hostname);

    VpnBypassDns dns = new VpnBypassDns(mockVpnManager, mockSystemDns);
    assertThat(dns.lookup(hostname)).contains(mockAddress);

    verify(mockVpnManager).getNetwork();
    verifyNoMoreInteractions(mockVpnManager);
    verify(mockSystemDns).lookup(hostname);
  }

  @Test
  public void lookup_usesNetworkWhenSet() throws Exception {
    String hostname = "foo.bar.baz";
    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.UNKNOWN_TYPE);
    doReturn(ppnNetwork).when(mockVpnManager).getNetwork();
    doReturn(new InetAddress[] {mockAddress}).when(mockNetwork).getAllByName(hostname);

    VpnBypassDns dns = new VpnBypassDns(mockVpnManager, mockSystemDns);
    assertThat(dns.lookup(hostname)).containsExactly(mockAddress);

    verify(mockVpnManager).getNetwork();
    verify(mockNetwork).getAllByName(hostname);
    verifyNoInteractions(mockSystemDns);
  }
}
