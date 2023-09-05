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

package com.google.android.libraries.privacy.ppn.internal.service;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.robolectric.Shadows.shadowOf;

import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.libraries.privacy.ppn.BypassOptions;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.android.libraries.privacy.ppn.internal.TunFdData.IpRange;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.common.collect.ImmutableSet;
import com.google.common.net.InetAddresses;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashSet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowVpnService;

/** Unit test for {@link RouteManager}. */
@RunWith(RobolectricTestRunner.class)
public class VpnManagerTest {
  @Rule public final MockitoRule mocks = MockitoJUnit.rule();

  // When possible, we use the ShadowVpnService for testing. But for tests where the Shadow is
  // incomplete, we use mocks.
  private VpnService service;
  @Mock private VpnServiceWrapper mockService;
  @Mock private VpnService.Builder mockBuilder;

  @Mock private Network mockNetwork;
  @Mock private ParcelFileDescriptor mockFd;

  private boolean isIpv4Addr(String addr) {
    return InetAddresses.forString(addr) instanceof Inet4Address;
  }

  private boolean isIpv6Addr(String addr) {
    return InetAddresses.forString(addr) instanceof Inet6Address;
  }

  private IpRange buildIpv4IpRange() {
    return IpRange.newBuilder()
        .setIpFamily(IpRange.IpFamily.IPV4)
        .setIpRange("0.0.0.0")
        .setPrefix(16)
        .build();
  }

  private IpRange buildIpv6IpRange() {
    return IpRange.newBuilder()
        .setIpFamily(IpRange.IpFamily.IPV6)
        .setIpRange("::1")
        .setPrefix(128)
        .build();
  }

  @Before
  public void setUp() {
    service = Robolectric.setupService(VpnService.class);
    doReturn(mockBuilder).when(mockService).newBuilder();
  }

  @Test
  public void setService_marksServiceAsRunning() {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    assertThat(manager.isRunning()).isFalse();

    manager.setService(service);

    assertThat(manager.isRunning()).isTrue();
  }

  @Test
  public void setServiceNull_marksServiceAsStopped() {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setService(service);
    assertThat(manager.isRunning()).isTrue();

    manager.setService(null);

    assertThat(manager.isRunning()).isFalse();
  }

  @Test
  public void stopService_tellsServiceToStop() {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setService(service);
    assertThat(manager.isRunning()).isTrue();

    manager.stopService();

    assertThat(manager.isRunning()).isTrue();
    shadowOf(service).isStoppedBySelf();
  }

  @Test
  public void switchNetwork_setsUnderlyingNetworks() {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(true).when(mockService).setUnderlyingNetworks(any());

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    verify(mockNetwork, atLeast(0)).getNetworkHandle();
    manager.setNetwork(ppnNetwork);

    ArgumentCaptor<Network[]> actualNetwork = ArgumentCaptor.forClass(Network[].class);
    verify(mockService).setUnderlyingNetworks(actualNetwork.capture());
    assertThat(actualNetwork.getValue()).asList().containsExactly(mockNetwork);

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void setBypassOptions_setsCorrectly() {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);

    assertThat(manager.disallowedApplications()).isEmpty();
    assertThat(manager.allowBypass()).isFalse();
    assertThat(manager.excludeLocalAddresses()).isTrue();

    BypassOptions bypassOptions =
        BypassOptions.builder()
            .setAllowBypass(true)
            .setExcludeLocalAddresses(false)
            .setDisallowedApplications(ImmutableSet.of("foo"))
            .build();
    manager.setBypassOptions(bypassOptions);

    assertThat(manager.disallowedApplications()).containsExactly("foo");
    assertThat(manager.allowBypass()).isTrue();
    assertThat(manager.excludeLocalAddresses()).isFalse();
  }

  @Test
  public void createTunFd_establishesTunFd() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(anyString(), anyInt());
    verify(mockBuilder).setMtu(anyInt());
    verify(mockBuilder).setMetered(anyBoolean());
    verify(mockBuilder).establish();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createTunFd_establishesTunFdWithIpv6() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    // Enable IPv6 in the options
    PpnOptions options = new PpnOptions.Builder().setIPv6Enabled(true).build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    IpRange ipv4Range = buildIpv4IpRange();
    IpRange ipv6Range = buildIpv6IpRange();
    // Create with an MTU of at least the IPv6 minimum of 1280
    TunFdData data =
        TunFdData.newBuilder()
            .setMtu(1280)
            .addTunnelIpAddresses(ipv4Range)
            .addTunnelIpAddresses(ipv6Range)
            .addTunnelDnsAddresses(ipv4Range)
            .addTunnelDnsAddresses(ipv6Range)
            .build();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addAddress(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addAddress(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addDnsServer(argThat(this::isIpv4Addr));
    verify(mockBuilder, atLeastOnce()).addDnsServer(argThat(this::isIpv6Addr));
    verify(mockBuilder).setMtu(1280);
    verify(mockBuilder).setMetered(anyBoolean());
    verify(mockBuilder).establish();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createTunFd_ipv6DisabledEstablishesTunFdWithoutIpv6() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    // Disable IPv6 in the options
    PpnOptions options = new PpnOptions.Builder().setIPv6Enabled(false).build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    IpRange ipv4Range = buildIpv4IpRange();
    IpRange ipv6Range = buildIpv6IpRange();
    // Create with an MTU of at least the IPv6 minimum of 1280
    TunFdData data =
        TunFdData.newBuilder()
            .setMtu(1280)
            .addTunnelIpAddresses(ipv4Range)
            .addTunnelIpAddresses(ipv6Range)
            .addTunnelDnsAddresses(ipv4Range)
            .addTunnelDnsAddresses(ipv6Range)
            .build();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addAddress(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, never()).addAddress(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addDnsServer(argThat(this::isIpv4Addr));
    verify(mockBuilder, never()).addDnsServer(argThat(this::isIpv6Addr));
    verify(mockBuilder).setMtu(1280);
    verify(mockBuilder).setMetered(anyBoolean());
    verify(mockBuilder).establish();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createTunFd_mtuUnderMinForIpv6EstablishesTunFdWithoutIpv6() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    IpRange ipv4Range = buildIpv4IpRange();
    IpRange ipv6Range = buildIpv6IpRange();
    // Create with an MTU less than the IPv6 minimum of 1280
    TunFdData data =
        TunFdData.newBuilder()
            .setMtu(1279)
            .addTunnelIpAddresses(ipv4Range)
            .addTunnelIpAddresses(ipv6Range)
            .addTunnelDnsAddresses(ipv4Range)
            .addTunnelDnsAddresses(ipv6Range)
            .build();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addRoute(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addAddress(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, never()).addAddress(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, atLeastOnce()).addDnsServer(argThat(this::isIpv4Addr));
    verify(mockBuilder, never()).addDnsServer(argThat(this::isIpv6Addr));
    verify(mockBuilder).setMtu(1279);
    verify(mockBuilder).setMetered(anyBoolean());
    verify(mockBuilder).establish();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createTunFd_setsDisallowedApplications() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setDisallowedApplications(new HashSet<>(Arrays.asList("foo", "bar", "baz")));
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(anyString(), anyInt());
    verify(mockBuilder).setMetered(anyBoolean());
    verify(mockBuilder).setMtu(anyInt());
    verify(mockBuilder).addDisallowedApplication("foo");
    verify(mockBuilder).addDisallowedApplication("bar");
    verify(mockBuilder).addDisallowedApplication("baz");
    verify(mockBuilder).establish();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createTunFd_bypassOptionsAllDisabled() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    PpnOptions options =
        new PpnOptions.Builder()
            .setAllowBypass(false)
            .setExcludeLocalAddresses(false)
            .setDisallowedApplications(ImmutableSet.of())
            .build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockBuilder).addRoute(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder).addRoute(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder, never()).allowBypass();
    verify(mockBuilder, never()).addDisallowedApplication(anyString());
  }

  @Test
  public void createTunFd_bypassOptionsAllEnabled() throws Exception {
    ImmutableSet<String> disallowedApplications = ImmutableSet.of("foo", "bar");

    ShadowVpnService.setPrepareResult(null);
    PpnOptions options =
        new PpnOptions.Builder()
            .setAllowBypass(true)
            .setExcludeLocalAddresses(true)
            .setDisallowedApplications(disallowedApplications)
            .build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockBuilder, atLeast(2)).addRoute(argThat(this::isIpv4Addr), anyInt());
    verify(mockBuilder, atLeast(2)).addRoute(argThat(this::isIpv6Addr), anyInt());
    verify(mockBuilder).allowBypass();
    verify(mockBuilder, atLeastOnce()).addDisallowedApplication(anyString());
  }

  @Test
  public void createProtectedDatagramSocket_protectsAndBindsSocket() throws Exception {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(0xfeed).when(mockFd).detachFd();
    doReturn(mockFd).when(mockService).parcelSocket(any(DatagramSocket.class));
    doReturn(true).when(mockService).protect(any(DatagramSocket.class));

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    verify(mockNetwork, atLeast(0)).getNetworkHandle();
    int fd = manager.createProtectedDatagramSocket(ppnNetwork);

    assertThat(fd).isEqualTo(0xfeed);

    ArgumentCaptor<DatagramSocket> socket = ArgumentCaptor.forClass(DatagramSocket.class);
    verify(mockService).protect(socket.capture());
    verify(mockNetwork).bindSocket(socket.getValue());
    verify(mockService).parcelSocket(socket.getValue());
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createProtectedStreamSocket_protectsAndBindsSocket() throws Exception {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(0xfeed).when(mockFd).detachFd();
    doReturn(mockFd).when(mockService).parcelSocket(any(Socket.class));
    doReturn(true).when(mockService).protect(any(Socket.class));

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    verify(mockNetwork, atLeast(0)).getNetworkHandle();
    int fd = manager.createProtectedStreamSocket(ppnNetwork);

    assertThat(fd).isEqualTo(0xfeed);

    ArgumentCaptor<Socket> socket = ArgumentCaptor.forClass(Socket.class);
    verify(mockService).protect(socket.capture());
    verify(mockNetwork).bindSocket(socket.getValue());
    verify(mockService).parcelSocket(socket.getValue());
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }

  @Test
  public void createProtectedStreamSocket_invalidFdFromSocket() throws Exception {
    PpnOptions options = new PpnOptions.Builder().build();
    VpnManager manager = VpnManager.create(ApplicationProvider.getApplicationContext(), options);
    manager.setServiceWrapper(mockService);
    doReturn(-1).when(mockFd).detachFd();
    doReturn(mockFd).when(mockService).parcelSocket(any(Socket.class));
    doReturn(true).when(mockService).protect(any(Socket.class));

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    verify(mockNetwork, atLeast(0)).getNetworkHandle();
    assertThrows(Exception.class, () -> manager.createProtectedStreamSocket(ppnNetwork));

    ArgumentCaptor<Socket> socket = ArgumentCaptor.forClass(Socket.class);
    verify(mockService).protect(socket.capture());
    verify(mockNetwork).bindSocket(socket.getValue());
    verify(mockService).parcelSocket(socket.getValue());
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }
}
