/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.libraries.privacy.ppn.internal.http;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import android.net.Network;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.common.net.InetAddresses;
import java.net.InetAddress;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(AndroidJUnit4.class)
public final class NetworkBoundDnsTest {

  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  private final InetAddress ipv4Address = InetAddresses.forString("127.0.0.1");
  private final InetAddress ipv6Address = InetAddresses.forString("::1");
  private final InetAddress[] addresses = {ipv4Address, ipv6Address};
  @Mock private Network mockNetwork;

  @Test
  public void lookup_allAddresses() throws Exception {
    NetworkBoundDns dns = new NetworkBoundDns(mockNetwork, AddressFamily.V4V6);

    when(mockNetwork.getAllByName(any())).thenReturn(addresses);

    List<InetAddress> lookupResult = dns.lookup("");

    assertThat(lookupResult).containsExactly(ipv4Address, ipv6Address);
  }

  @Test
  public void lookup_onlyIpv4() throws Exception {
    NetworkBoundDns dns = new NetworkBoundDns(mockNetwork, AddressFamily.V4);

    when(mockNetwork.getAllByName(any())).thenReturn(addresses);

    List<InetAddress> lookupResult = dns.lookup("");

    assertThat(lookupResult).containsExactly(ipv4Address);
  }

  @Test
  public void lookup_onlyIpv6() throws Exception {
    NetworkBoundDns dns = new NetworkBoundDns(mockNetwork, AddressFamily.V6);

    when(mockNetwork.getAllByName(any())).thenReturn(addresses);

    List<InetAddress> lookupResult = dns.lookup("");

    assertThat(lookupResult).containsExactly(ipv6Address);
  }
}
