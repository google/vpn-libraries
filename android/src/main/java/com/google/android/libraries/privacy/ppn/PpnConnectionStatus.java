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

package com.google.android.libraries.privacy.ppn;

import static java.util.stream.Collectors.toMap;

import com.google.android.libraries.privacy.ppn.internal.ConnectionStatus;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import java.util.Arrays;
import java.util.Map;

/**
 * Status of a PpnConnection.
 */
public final class PpnConnectionStatus {
  /*
   * Internally, we represent the connection status as a ConnectionStatus proto. This class wraps
   * that proto with an API for public use, so that we have the option of changing our internal
   * implementation without breaking clients.
   */

  /** All possible network types supported by PPN. */
  public enum PpnNetworkType {
    UNKNOWN(NetworkType.UNKNOWN_TYPE),
    CELLULAR(NetworkType.CELLULAR),
    WIFI(NetworkType.WIFI);

    private final NetworkType value;

    PpnNetworkType(NetworkType value) {
      this.value = value;
    }

    NetworkType protoValue() {
      return value;
    }

    private static final Map<NetworkType, PpnNetworkType> protoToEnum =
        Arrays.stream(values()).collect(toMap(PpnNetworkType::protoValue, e -> e));

    static PpnNetworkType fromProtoValue(NetworkType value) throws PpnException {
      PpnNetworkType type = protoToEnum.get(value);
      if (type == null) {
        throw new PpnException("Invalid network type: " + value.getNumber());
      }
      return type;
    }
  }

  /** All possible Security levels supported by a PpnConnection. */
  public enum Security {
    UNKNOWN(ConnectionStatus.Security.UNKNOWN_SECURITY),
    SECURE(ConnectionStatus.Security.SECURE),
    INSECURE(ConnectionStatus.Security.INSECURE);

    private final ConnectionStatus.Security value;

    Security(ConnectionStatus.Security value) {
      this.value = value;
    }

    ConnectionStatus.Security protoValue() {
      return value;
    }

    private static final Map<ConnectionStatus.Security, Security> protoToEnum =
        Arrays.stream(values()).collect(toMap(Security::protoValue, e -> e));

    static Security fromProtoValue(ConnectionStatus.Security value) throws PpnException {
      Security security = protoToEnum.get(value);
      if (security == null) {
        throw new PpnException("Invalid security: " + value.getNumber());
      }
      return security;
    }
  }

  /**
   * All possible connection quality supported by a PpnConnection according to RSSI.
   * https://wiki.teltonika-networks.com/view/Mobile_Signal_Strength_Recommendations
   */
  public enum ConnectionQuality {
    UNKNOWN(ConnectionStatus.ConnectionQuality.UNKNOWN_QUALITY),
    EXCELLENT(ConnectionStatus.ConnectionQuality.EXCELLENT),
    GOOD(ConnectionStatus.ConnectionQuality.GOOD),
    FAIR(ConnectionStatus.ConnectionQuality.FAIR),
    POOR(ConnectionStatus.ConnectionQuality.POOR),
    NO_SIGNAL(ConnectionStatus.ConnectionQuality.NO_SIGNAL);

    private final ConnectionStatus.ConnectionQuality value;

    ConnectionQuality(ConnectionStatus.ConnectionQuality value) {
      this.value = value;
    }

    ConnectionStatus.ConnectionQuality protoValue() {
      return value;
    }

    private static final Map<ConnectionStatus.ConnectionQuality, ConnectionQuality> protoToEnum =
        Arrays.stream(values()).collect(toMap(ConnectionQuality::protoValue, e -> e));

    static ConnectionQuality fromProtoValue(ConnectionStatus.ConnectionQuality value)
        throws PpnException {
      ConnectionQuality quality = protoToEnum.get(value);
      if (quality == null) {
        throw new PpnException("Invalid connection quality: " + value.getNumber());
      }
      return quality;
    }
  }

  // Network Name of the PpnConnection. If on Cellular, NetworkName will be the cellular network
  // name (i.e. AT&T, Verizon, etc).
  private final String networkName;
  private final PpnNetworkType networkType;
  private final Security security;
  private final ConnectionQuality connectionQuality;

  private PpnConnectionStatus(
      String networkName,
      PpnNetworkType networkType,
      Security security,
      ConnectionQuality connectionQuality) {
    this.networkName = networkName;
    this.networkType = networkType;
    this.security = security;
    this.connectionQuality = connectionQuality;
  }

  /** Returns the name of the WiFi network or cellular provider. */
  public String getNetworkName() {
    return networkName;
  }

  /** Returns the type of the network, such as WiFi or Cellular. */
  public PpnNetworkType getNetworkType() {
    return networkType;
  }

  /** Returns the security level of the network, i.e. whether the WiFi is secure. */
  public Security getSecurity() {
    return security;
  }

  /** Returns the current quality of the connection, from NO_SIGNAL to EXCELLENT. */
  public ConnectionQuality getConnectionQuality() {
    return connectionQuality;
  }

  @Override
  public String toString() {
    return "{ Network: "
        + networkName
        + ", Type: "
        + networkType
        + ", Security: "
        + security
        + ", Quality: "
        + connectionQuality
        + " }";
  }

  /**
   * Converts this object into its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it
   * returns an internal class, so it's not part of the supported public API.
   */
  public ConnectionStatus toProto() {
    return ConnectionStatus.newBuilder()
        .setNetworkName(networkName)
        .setNetworkType(networkType.protoValue())
        .setSecurity(security.protoValue())
        .setQuality(connectionQuality.protoValue())
        .build();
  }

  /*
   * Creates a PpnConnectionStatus from its proto representation.
   *
   * <p>This method is public so that it can be accessed by other packages within PPN, but it takes
   * an internal class, so it's not part of the supported public API.
   */
  public static PpnConnectionStatus fromProto(ConnectionStatus status) throws PpnException {
    return new PpnConnectionStatus(
        status.getNetworkName(),
        PpnNetworkType.fromProtoValue(status.getNetworkType()),
        Security.fromProtoValue(status.getSecurity()),
        ConnectionQuality.fromProtoValue(status.getQuality()));
  }
}
