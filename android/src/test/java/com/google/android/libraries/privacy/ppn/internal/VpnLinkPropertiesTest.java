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

import static com.google.common.truth.Truth.assertThat;

import android.net.LinkProperties;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class VpnLinkPropertiesTest {

  @Test
  public void equals_equalsSucceeds() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties1 = VpnLinkProperties.fromLinkProperties(linkProperties);
    VpnLinkProperties vpnLinkProperties2 = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties1.equals(vpnLinkProperties2)).isTrue();
  }

  @Test
  public void equals_equalsFailsWithDifferentInterfaceName() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties1 = VpnLinkProperties.fromLinkProperties(linkProperties);

    linkProperties.setInterfaceName("Test2");

    VpnLinkProperties vpnLinkProperties2 = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties1.equals(vpnLinkProperties2)).isFalse();
  }

  @Test
  public void equals_equalsFailsWithDifferentMtu() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties1 = VpnLinkProperties.fromLinkProperties(linkProperties);

    linkProperties.setMtu(5678);

    VpnLinkProperties vpnLinkProperties2 = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties1.equals(vpnLinkProperties2)).isFalse();
  }

  @Test
  public void hashCode_consistentValueReturned() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties.hashCode()).isEqualTo(vpnLinkProperties.hashCode());
  }

  @Test
  public void hashCode_interfaceNameChangesValue() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties1 = VpnLinkProperties.fromLinkProperties(linkProperties);

    linkProperties.setInterfaceName("Test2");

    VpnLinkProperties vpnLinkProperties2 = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties1.hashCode()).isNotEqualTo(vpnLinkProperties2.hashCode());
  }

  @Test
  public void hashCode_mtuChangesValue() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties1 = VpnLinkProperties.fromLinkProperties(linkProperties);

    linkProperties.setMtu(5678);

    VpnLinkProperties vpnLinkProperties2 = VpnLinkProperties.fromLinkProperties(linkProperties);

    assertThat(vpnLinkProperties1.hashCode()).isNotEqualTo(vpnLinkProperties2.hashCode());
  }

  @Test
  public void toString_returnsFormattedString() throws Exception {
    LinkProperties linkProperties = new LinkProperties();
    linkProperties.setInterfaceName("Test");
    linkProperties.setMtu(1234);

    VpnLinkProperties vpnLinkProperties = VpnLinkProperties.fromLinkProperties(linkProperties);

    String result = vpnLinkProperties.toString();
    assertThat(result).contains("Test");
    assertThat(result).contains("1234");
    assertThat(result).contains("[]");
  }
}
