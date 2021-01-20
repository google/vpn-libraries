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

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.TunFdData;
import com.google.android.libraries.privacy.ppn.krypton.KryptonException;
import com.google.android.libraries.privacy.ppn.krypton.KryptonIpSecHelper;
import com.google.android.libraries.privacy.ppn.krypton.KryptonIpSecHelperImpl;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;

/**
 * Wrapper around a mutable VpnService that deals with the details about how to use the service to
 * implement a VPN for PPN. The underlying service will be null if the service is not running.
 */
public class VpnManager {
  private static final String TAG = "VpnManager";

  // The optimal Socket Buffer Size from GCS experimentation is 4MB.
  private static final int SOCKET_BUFFER_SIZE_BYTES = 4 * 1024 * 1024;

  // TODO: Investigate how to instantiate ipSecHelper from a constructor.
  // KrytonIpSecHelper for handling an IpSecManager instance.
  @Nullable private KryptonIpSecHelper ipSecHelper = null;

  private final Context context;
  private final PpnOptions options;

  // The underlying VpnService this manager is managing.
  // This may be null if the service is not running.
  @Nullable private volatile VpnServiceWrapper vpnService;

  @Nullable private volatile PpnNetwork network;

  public VpnManager(Context context, PpnOptions options) {
    this.context = context;
    this.options = options;
  }

  /**
   * Resets the underlying service for this manager. This should be called whenever a service starts
   * or stops.
   */
  public void setService(@Nullable VpnService service) {
    setServiceWrapper(service == null ? null : new VpnServiceWrapper(service));
  }

  public void setIpSecHelper(KryptonIpSecHelper ipSecHelper) {
    this.ipSecHelper = ipSecHelper;
  }

  public void configureIpSec(IpSecTransformParams params) throws PpnException {
    if (ipSecHelper == null) {
      ipSecHelper = new KryptonIpSecHelperImpl(context);
    }
    if (ipSecHelper != null) {
      try {
        ipSecHelper.transformFd(params);
      } catch (KryptonException e) {
        throw new PpnException("Error encountered when configuring IpSec.", e);
      }
    } else {
      throw new PpnException(
          "Error encountered when configuring IpSec: No KryptonIpSecHelper set.");
    }
  }

  @VisibleForTesting
  void setServiceWrapper(@Nullable VpnServiceWrapper service) {
    this.vpnService = service;
  }

  /** Stops the underlying Service, if one is running. Otherwise, does nothing. */
  public void stopService() {
    VpnServiceWrapper service = vpnService;
    if (service != null) {
      service.stopSelf();
    }
  }

  /** Returns whether the underlying service has been set. */
  public boolean isRunning() {
    return vpnService != null;
  }

  /** Tells the service to set its underlying network to the given network. */
  public void setNetwork(PpnNetwork ppnNetwork) {
    network = ppnNetwork;
    VpnServiceWrapper service = vpnService;
    if (service != null) {
      service.setUnderlyingNetworks(new Network[] {ppnNetwork.getNetwork()});
    } else {
      Log.w(TAG, "Failed to set underlying network because service is not running.");
    }
  }

  /** Gets the underlying network for the service. */
  public PpnNetwork getNetwork() {
    return network;
  }

  /**
   * Establishes the VpnService and creates the TUN fd for processing requests from the device. This
   * can only be called after onStartService and before onStartService.
   *
   * @param tunFdData the data needed to create a TUN Fd.
   * @return the file descriptor of the TUN. The receiver is responsible for closing it eventually.
   * @throws PpnException if the service has not been set.
   */
  public int createTunFd(TunFdData tunFdData) throws PpnException {
    VpnServiceWrapper service = vpnService;
    if (service == null) {
      throw new PpnException("Tried to create a TUN fd when PPN service wasn't running.");
    }

    if (VpnService.prepare(context) != null) {
      throw new PpnException("VpnService was not prepared or was revoked.");
    }

    VpnService.Builder builder = service.newBuilder();
    setVpnServiceParametersFromOptions(builder, options);
    setVpnServiceParametersFromTunFdData(builder, tunFdData);

    ParcelFileDescriptor tunFds;
    try {
      Log.w(TAG, "Establishing Tun FD");
      tunFds = builder.establish();
    } catch (RuntimeException e) {
      Log.e(TAG, "Failure when establishing Tun FD.", e);
      throw new PpnException("Failure when establishing TUN FD.", e);
    }
    if (tunFds == null) {
      throw new PpnException("establish() returned null. The VpnService was probably revoked.");
    }
    int fd = tunFds.detachFd();
    if (fd <= 0) {
      throw new PpnException("Invalid TUN fd: " + fd);
    }
    return fd;
  }

  private static void setVpnServiceParametersFromOptions(
      VpnService.Builder builder, PpnOptions options) {
    for (String packageName : options.getDisallowedApplications()) {
      try {
        builder.addDisallowedApplication(packageName);
      } catch (NameNotFoundException e) {
        Log.e(TAG, "Disallowed application package not found: " + packageName, e);
      }
    }
  }

  private static void setVpnServiceParametersFromTunFdData(
      VpnService.Builder builder, TunFdData tunFdData) {
    if (tunFdData.hasSessionName()) {
      builder.setSession(tunFdData.getSessionName());
    }

    if (tunFdData.hasMtu()) {
      builder.setMtu(tunFdData.getMtu());
    }

    // VpnService.Builder.setMetered(...) is only supported in API 29+.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      Log.w(TAG, "Setting metered to " + tunFdData.getIsMetered());
      builder.setMetered(tunFdData.getIsMetered());
    }

    for (TunFdData.IpRange ipRange : tunFdData.getTunnelIpAddressesList()) {
      builder.addAddress(ipRange.getIpRange(), ipRange.getPrefix());
    }
    for (TunFdData.IpRange ipRange : tunFdData.getTunnelDnsAddressesList()) {
      Log.w(TAG, "Adding DNS: " + ipRange.getIpRange());
      builder.addDnsServer(ipRange.getIpRange());
    }
    for (TunFdData.IpRange ipRange : tunFdData.getTunnelRoutesList()) {
      builder.addRoute(ipRange.getIpRange(), ipRange.getPrefix());
    }

    RouteManager.addRoutes(builder);
  }

  /**
   * Creates a new protected UDP socket, which can be used by Krypton for connecting to Copper. This
   * can only be called after onStartService and before onStopService.
   *
   * @param ppnNetwork PpnNetwork to bind to.
   * @return the file descriptor of the socket. The receiver is responsible for closing it.
   * @throws PpnException if the service has not been set.
   */
  public int createProtectedDatagramSocket(PpnNetwork ppnNetwork) throws PpnException {
    return createProtectedDatagramSocket(ppnNetwork.getNetwork());
  }

  /**
   * Creates a new protected UDP socket, which can be used by Krypton for connecting to Copper. This
   * can only be called after onStartService and before onStopService.
   *
   * @param network Network to bind to.
   * @return the file descriptor of the socket. The receiver is responsible for closing it.
   * @throws PpnException if the service has not been set.
   */
  private int createProtectedDatagramSocket(Network network) throws PpnException {
    VpnServiceWrapper service = vpnService;
    if (service == null) {
      throw new PpnException("Tried to create a protected socket when PPN service wasn't running.");
    }
    DatagramSocket socket = null;

    try {
      socket = new DatagramSocket();
      socket.setReceiveBufferSize(SOCKET_BUFFER_SIZE_BYTES);
      socket.setSendBufferSize(SOCKET_BUFFER_SIZE_BYTES);

      service.protect(socket);
      network.bindSocket(socket);

      // We need to explicitly duplicate the socket otherwise it will fail for Android version 9
      // (P) and older.
      // TODO: Find a cleaner way to support both versions.
      ParcelFileDescriptor pfd = service.parcelSocket(socket).dup();
      // ParcelFileDescriptor duplicates the socket, so the original needs to be closed.
      socket.close();
      int fd = pfd.detachFd();
      if (fd <= 0) {
        throw new PpnException("Invalid file descriptor from datagram socket: " + fd);
      }
      return fd;
    } catch (IOException e) {
      if (socket != null) {
        socket.close();
      }
      throw new PpnException("Unable to create socket or bind network to socket.", e);
    }
  }

  /**
   * Protects the given socket if the VpnService is running. Otherwise, does nothing. This is useful
   * for making TCP connections that should always bypass the VPN.
   */
  void protect(Socket socket) {
    VpnServiceWrapper service = vpnService;
    if (service != null) {
      service.protect(socket);
    }
  }
}
