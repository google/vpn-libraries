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

import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import com.google.errorprone.annotations.ResultIgnorabilityUnspecified;
import java.net.DatagramSocket;
import java.net.Socket;

/**
 * Wraps a VpnService with a testable interface.
 *
 * <p>VpnService is marked as final, so it can't be mocked. But ShadowVpnService is quite
 * incomplete, and also has no way to provide a mock Builder. So we need to wrap all access to the
 * VpnService so that we can mock the wrapper to test classes that use VpnService.
 */
class VpnServiceWrapper {
  private final VpnService service;

  public VpnServiceWrapper(VpnService service) {
    if (service == null) {
      throw new IllegalArgumentException("VpnServiceWrapper cannot have a null VpnService.");
    }
    this.service = service;
  }

  public void stopSelf() {
    service.stopSelf();
  }

  @ResultIgnorabilityUnspecified
  public boolean setUnderlyingNetworks(Network[] networks) {
    return service.setUnderlyingNetworks(networks);
  }

  @ResultIgnorabilityUnspecified
  public boolean protect(DatagramSocket socket) {
    return service.protect(socket);
  }

  @ResultIgnorabilityUnspecified
  public boolean protect(Socket socket) {
    return service.protect(socket);
  }

  public VpnService.Builder newBuilder() {
    return service.new Builder();
  }

  // ParcelFileDescriptor.fromDatagramSocket does not work in robolectric tests, so we use this
  // method to make it mockable.
  public ParcelFileDescriptor parcelSocket(DatagramSocket socket) {
    return ParcelFileDescriptor.fromDatagramSocket(socket);
  }

  // ParcelFileDescriptor.fromSocket does not work in robolectric tests, so we use this
  // method to make it mockable.
  public ParcelFileDescriptor parcelSocket(Socket socket) {
    return ParcelFileDescriptor.fromSocket(socket);
  }
}
