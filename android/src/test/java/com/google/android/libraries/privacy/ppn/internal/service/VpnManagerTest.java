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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.robolectric.Shadows.shadowOf;

import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.testing.mockito.Mocks;
import java.net.DatagramSocket;
import java.util.Arrays;
import java.util.HashSet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowVpnService;

/** Unit test for {@link RouteManager}. */
@RunWith(RobolectricTestRunner.class)
@Config(shadows = {ShadowVpnService.class})
public class VpnManagerTest {
  @Rule public Mocks mocks = new Mocks(this);

  // When possible, we use the ShadowVpnService for testing. But for tests where the Shadow is
  // incomplete, we use mocks.
  private VpnService service;
  @Mock private VpnServiceWrapper mockService;
  @Mock private VpnService.Builder mockBuilder;
  @Mock private PpnOptions mockOptions;

  @Mock private Network mockNetwork;
  @Mock private ParcelFileDescriptor mockFd;

  @Before
  public void setUp() {
    service = Robolectric.setupService(VpnService.class);
    doReturn(mockBuilder).when(mockService).newBuilder();
  }

  @Test
  public void setService_marksServiceAsRunning() {
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    assertThat(manager.isRunning()).isFalse();

    manager.setService(service);

    assertThat(manager.isRunning()).isTrue();
  }

  @Test
  public void setServiceNull_marksServiceAsStopped() {
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setService(service);
    assertThat(manager.isRunning()).isTrue();

    manager.setService(null);

    assertThat(manager.isRunning()).isFalse();
  }

  @Test
  public void stopService_tellsServiceToStop() {
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setService(service);
    assertThat(manager.isRunning()).isTrue();

    manager.stopService();

    assertThat(manager.isRunning()).isTrue();
    shadowOf(service).isStoppedBySelf();
  }

  @Test
  public void switchNetwork_setsUnderlyingNetworks() {
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setServiceWrapper(mockService);

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
  public void createTunFd_establishesASocket() throws Exception {
    ShadowVpnService.setPrepareResult(null);
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(anyString(), anyInt());
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
    doReturn(new HashSet<>(Arrays.asList("foo", "bar", "baz")))
        .when(mockOptions)
        .getDisallowedApplications();
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setServiceWrapper(mockService);
    doReturn(mockFd).when(mockBuilder).establish();
    doReturn(0xdead).when(mockFd).detachFd();

    TunFdData data = TunFdData.getDefaultInstance();
    int fd = manager.createTunFd(data);

    assertThat(fd).isEqualTo(0xdead);

    verify(mockService).newBuilder();
    verify(mockBuilder, atLeastOnce()).addRoute(anyString(), anyInt());
    verify(mockBuilder).setMetered(anyBoolean());
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
  public void createProtectedDatagramSocket_protectsAndBindsSocket() throws Exception {
    VpnManager manager = new VpnManager(ApplicationProvider.getApplicationContext(), mockOptions);
    manager.setServiceWrapper(mockService);
    doReturn(0xfeed).when(mockFd).detachFd();
    doReturn(mockFd).when(mockService).parcelSocket(any(DatagramSocket.class));
    doReturn(mockFd).when(mockFd).dup();

    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    verify(mockNetwork, atLeast(0)).getNetworkHandle();
    int fd = manager.createProtectedDatagramSocket(ppnNetwork);

    assertThat(fd).isEqualTo(0xfeed);

    ArgumentCaptor<DatagramSocket> socket = ArgumentCaptor.forClass(DatagramSocket.class);
    verify(mockService).protect(socket.capture());
    verify(mockNetwork).bindSocket(socket.getValue());
    verify(mockService).parcelSocket(socket.getValue());
    verify(mockFd).dup();
    verify(mockFd).detachFd();

    verifyNoMoreInteractions(mockService);
    verifyNoMoreInteractions(mockBuilder);
    verifyNoMoreInteractions(mockNetwork);
    verifyNoMoreInteractions(mockFd);
  }
}
