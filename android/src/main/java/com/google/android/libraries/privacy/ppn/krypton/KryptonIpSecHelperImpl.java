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

package com.google.android.libraries.privacy.ppn.krypton;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecManager.ResourceUnavailableException;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.SpiUnavailableException;
import android.net.IpSecTransform;
import android.net.Network;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;
import com.google.protobuf.ByteString;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/** Implementation of KryptonIpSecHelper. */
public final class KryptonIpSecHelperImpl implements KryptonIpSecHelper {
  private final Context context;
  private final IpSecManager ipSecManager;

  public KryptonIpSecHelperImpl(Context context) {
    this.context = context;
    this.ipSecManager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
  }

  @Override
  public void transformFd(IpSecTransformParams params) throws KryptonException {
    ParcelFileDescriptor fd;
    try {
      fd = ParcelFileDescriptor.fromFd(params.getNetworkFd());
    } catch (IOException e) {
      throw new KryptonException("Unable to create ParcelFileDescriptor to transform.", e);
    }

    // TODO: Figure out Android API 22-28 support for fromNetworkHandle(...).
    Network network = Network.fromNetworkHandle(params.getNetworkId());

    InetAddress destinationAddress;
    try {
      destinationAddress = getDestinationAddress(network, params.getDestinationAddress());
    } catch (UnknownHostException e) {
      throw new KryptonException("Unable to resolve destination address for transform.", e);
    }

    InetAddress localAddress;
    try {
      localAddress = getLocalAddress(network, destinationAddress);
    } catch (Exception e) {
      throw new KryptonException("Unable to get local address for transform.", e);
    }

    try {
      // uplink SPI is the remote server SPI.
      SecurityParameterIndex uplinkSpi =
          ipSecManager.allocateSecurityParameterIndex(destinationAddress, params.getUplinkSpi());

      // downlink SPI is the local SPI.
      SecurityParameterIndex downlinkSpi =
          ipSecManager.allocateSecurityParameterIndex(localAddress, params.getDownlinkSpi());

      IpSecTransform outTransform =
          buildTransform(
              destinationAddress,
              uplinkSpi,
              getKeyingMaterial(params.getUplinkKey(), params.getUplinkSalt()));

      IpSecTransform inTransform =
          buildTransform(
              localAddress,
              downlinkSpi,
              getKeyingMaterial(params.getDownlinkKey(), params.getDownlinkSalt()));

      ipSecManager.applyTransportModeTransform(
          fd.getFileDescriptor(), IpSecManager.DIRECTION_IN, inTransform);
      ipSecManager.applyTransportModeTransform(
          fd.getFileDescriptor(), IpSecManager.DIRECTION_OUT, outTransform);
    } catch (ResourceUnavailableException | SpiUnavailableException | IOException e) {
      throw new KryptonException("Unable to apply IPSec transforms to fd.", e);
    }
  }

  @Override
  public void removeTransformFromFd(int networkFd) throws KryptonException {
    try {
      ipSecManager.removeTransportModeTransforms(ParcelFileDescriptor.fromFd(networkFd).getFileDescriptor());
    } catch (IOException e) {
      throw new KryptonException("Error encountered when removing transform from fd.", e);
    }
  }

  private static InetAddress getDestinationAddress(Network network, String destinationAddress)
      throws UnknownHostException {
    return network.getByName(destinationAddress);
  }

  private static InetAddress getLocalAddress(Network network, InetAddress destination)
      throws Exception {
    boolean isIpv4 = (destination instanceof Inet4Address);

    FileDescriptor sock =
        Os.socket(
            isIpv4 ? OsConstants.AF_INET : OsConstants.AF_INET6,
            OsConstants.SOCK_DGRAM,
            OsConstants.IPPROTO_UDP);
    network.bindSocket(sock);
    Os.connect(sock, destination, 443);
    InetSocketAddress localAddr = (InetSocketAddress) Os.getsockname(sock);
    Os.close(sock);
    return localAddr.getAddress();
  }

  private IpSecTransform buildTransform(
      InetAddress address, SecurityParameterIndex spi, byte[] keyMat)
      throws ResourceUnavailableException, SpiUnavailableException, IOException {
    IpSecAlgorithm algorithm = new IpSecAlgorithm(IpSecAlgorithm.AUTH_CRYPT_AES_GCM, keyMat);
    IpSecTransform transform =
        new IpSecTransform.Builder(context)
            .setAuthenticatedEncryption(algorithm)
            .buildTransportModeTransform(address, spi);
    return transform;
  }

  private static byte[] getKeyingMaterial(ByteString keyByteString, ByteString saltByteString) {
    byte[] key = keyByteString.toByteArray();
    byte[] salt = saltByteString.toByteArray();
    byte[] keyMat = Arrays.copyOf(key, key.length + salt.length);
    System.arraycopy(salt, 0, keyMat, key.length, salt.length);
    return keyMat;
  }
}
