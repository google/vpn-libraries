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

package com.google.android.libraries.privacy.ppn.krypton;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.SpiUnavailableException;
import android.net.IpSecTransform;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.Xenon;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/** Implementation of KryptonIpSecHelper. */
public final class KryptonIpSecHelperImpl implements KryptonIpSecHelper {
  private static final String TAG = "KryptonIpSecHelperImpl";

  private final Context context;
  private final Xenon xenon;

  private final IpSecManager ipSecManager;
  @Nullable private SecurityParameterIndex uplinkSpi = null;
  @Nullable private SecurityParameterIndex downlinkSpi = null;
  @Nullable private IpSecTransform inTransform = null;
  @Nullable private IpSecTransform outTransform = null;
  @Nullable private IpSecManager.UdpEncapsulationSocket encapsulationSocket = null;
  @Nullable private KryptonKeepaliveHelper keepaliveHelper = null;

  // A lock guarding all of the mutable state of this class.
  private final Object lock = new Object();

  public KryptonIpSecHelperImpl(Context context, Xenon xenon) {
    this.context = context;
    this.ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
    this.xenon = xenon;
  }

  /** Closes any objects allocated for the IpSecManager. */
  private void close() {
    synchronized (lock) {
      if (uplinkSpi != null) {
        uplinkSpi.close();
        uplinkSpi = null;
      }
      if (downlinkSpi != null) {
        downlinkSpi.close();
        downlinkSpi = null;
      }
      if (inTransform != null) {
        inTransform.close();
        inTransform = null;
      }
      if (outTransform != null) {
        outTransform.close();
        outTransform = null;
      }
      if (keepaliveHelper != null) {
        keepaliveHelper.stopKeepalive();
      }
      if (encapsulationSocket != null) {
        try {
          encapsulationSocket.close();
          encapsulationSocket = null;
        } catch (IOException e) {
          Log.w(TAG, "Exception while closing encapsulation socket.", e);
        }
      }
    }
  }

  @Override
  public void transformFd(IpSecTransformParams params, Runnable keepaliveStartCallback)
      throws KryptonException {
    Log.w(TAG, "Setting up transformFd for network = " + params.getNetworkId());
    PpnNetwork ppnNetwork = xenon.getNetwork(params.getNetworkId());
    if (ppnNetwork == null) {
      throw new KryptonException("Unable to fetch network with id " + params.getNetworkId());
    }

    InetAddress destinationAddress;
    try {
      destinationAddress = getDestinationAddress(ppnNetwork, params.getDestinationAddress());
    } catch (UnknownHostException e) {
      throw new KryptonException("Unable to resolve destination address for transform.", e);
    }

    InetAddress localAddress;
    try {
      localAddress = getLocalAddress(ppnNetwork, destinationAddress);
    } catch (Exception e) {
      throw new KryptonException(
          "Unable to get local address for " + destinationAddress + " for transform.", e);
    }

    synchronized (lock) {
      // If any of these members are already set, clear them.
      close();

      // Temporarily give ownership of the fd to a ParcelFileDescriptor so that we can pass it to
      // the VpnService APIs.
      ParcelFileDescriptor fd = ParcelFileDescriptor.adoptFd(params.getNetworkFd());

      try {
        // uplink SPI is the remote server SPI.
        if (params.getUplinkSpi() == 0) {
          throw new KryptonException("missing uplink spi");
        }
        uplinkSpi =
            ipSecManager.allocateSecurityParameterIndex(destinationAddress, params.getUplinkSpi());

        // downlink SPI is the local SPI.
        if (params.getDownlinkSpi() == 0) {
          throw new KryptonException("missing downlink spi");
        }
        downlinkSpi =
            ipSecManager.allocateSecurityParameterIndex(localAddress, params.getDownlinkSpi());

        if (params.getDestinationAddressFamily() == AddressFamily.V4) {
          encapsulationSocket = ipSecManager.openUdpEncapsulationSocket();
        }

        outTransform =
            buildTransform(
                localAddress,
                uplinkSpi,
                getKeyingMaterial(params.getUplinkKey(), params.getUplinkSalt()),
                params.getDestinationPort());

        inTransform =
            buildTransform(
                destinationAddress,
                downlinkSpi,
                getKeyingMaterial(params.getDownlinkKey(), params.getDownlinkSalt()),
                params.getDestinationPort());

        ipSecManager.applyTransportModeTransform(
            fd.getFileDescriptor(), IpSecManager.DIRECTION_IN, inTransform);
        ipSecManager.applyTransportModeTransform(
            fd.getFileDescriptor(), IpSecManager.DIRECTION_OUT, outTransform);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && encapsulationSocket != null) {
          if (keepaliveHelper == null) {
            keepaliveHelper = new KryptonKeepaliveHelperImpl(context);
          }

          keepaliveHelper.startKeepalive(
              ppnNetwork.getNetwork(),
              encapsulationSocket,
              localAddress,
              destinationAddress,
              params.getKeepaliveIntervalSeconds(),
              keepaliveStartCallback);
        }
      } catch (Exception e) {
        close();
        throw new KryptonException("Unable to apply IpSec transforms to fd.", e);
      } finally {
        // The ParcelFileDescriptor shouldn't own the fd anymore. Krypton is responsible for it.
        fd.detachFd();
      }
    }
  }

  @Override
  public void removeTransformFromFd(int networkFd) throws KryptonException {
    try {
      Log.w(TAG, "Removing transforms.");
      ipSecManager.removeTransportModeTransforms(
          ParcelFileDescriptor.fromFd(networkFd).getFileDescriptor());
      close();
    } catch (IOException e) {
      throw new KryptonException("Error encountered when removing transform from fd.", e);
    }
  }

  private static InetAddress getDestinationAddress(PpnNetwork network, String destinationAddress)
      throws UnknownHostException {
    return network.getNetwork().getByName(destinationAddress);
  }

  private InetAddress getLocalAddress(PpnNetwork network, InetAddress destination)
      throws Exception {
    DatagramSocket socket = new DatagramSocket();
    try {
      network.getNetwork().bindSocket(socket);
      socket.connect(destination, 443);
      if (socket.getLocalAddress().isAnyLocalAddress()) {
        throw new KryptonException(
            "Local address is wildcard address. This usually means the network does not support"
                + " the same protocol (IPv4 vs IPv6) as the remote address.");
      }
      return socket.getLocalAddress();
    } finally {
      socket.close();
    }
  }

  private IpSecTransform buildTransform(
      InetAddress address, SecurityParameterIndex spi, byte[] keyMaterial, int remotePort)
      throws ResourceUnavailableException, SpiUnavailableException, IOException {
    IpSecAlgorithm algorithm =
        new IpSecAlgorithm(IpSecAlgorithm.AUTH_CRYPT_AES_GCM, keyMaterial, 128);
    IpSecTransform.Builder builder =
        new IpSecTransform.Builder(context).setAuthenticatedEncryption(algorithm);

    if (encapsulationSocket != null) {
      builder = builder.setIpv4Encapsulation(encapsulationSocket, remotePort);
    }

    return builder.buildTransportModeTransform(address, spi);
  }

  private static byte[] getKeyingMaterial(ByteString keyByteString, ByteString saltByteString) {
    byte[] key = keyByteString.toByteArray();
    byte[] salt = saltByteString.toByteArray();
    byte[] keyMat = Arrays.copyOf(key, key.length + salt.length);
    System.arraycopy(salt, 0, keyMat, key.length, salt.length);
    return keyMat;
  }
}
