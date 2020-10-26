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

package com.google.android.libraries.privacy.ppn.internal.service.netmath;

import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.internal.service.netmath.IpRange.NumBits;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents an immutable CIDR (Classless Inter-Domain Routing) notation.
 *
 * <p>This supports both IPv4 and IPv6. Examples include 192.0.2.0/24 for IPv4, and 2001:db8::/32
 * for IPv6, as defined in RFC 4632 and RFC 4291.
 */
public class Cidr {

  private static final Pattern CIDR_REGEX = Pattern.compile("(.+?)/(\\d+)");

  private final BigInteger ipBits;
  private final @NumBits int ipLength;
  private final int prefixBits;

  Cidr(BigInteger ipBits, @NumBits int ipLength, int prefixBits) {
    this.ipBits = ipBits;
    this.ipLength = ipLength;
    this.prefixBits = prefixBits;
  }

  /**
   * Creates Cidr from a host address and prefix length.
   *
   * @throws IllegalArgumentException if {@code prefixBits} is out of range
   */
  public Cidr(InetAddress address, int prefixBits) {
    this.prefixBits = prefixBits;
    ipBits = new BigInteger(1, address.getAddress());
    if (address instanceof Inet4Address) {
      if (this.prefixBits < 0 || this.prefixBits > NumBits.IPV4) {
        throw new IllegalArgumentException(
            String.format("IPv4 prefix %d is out of range", this.prefixBits));
      }
      ipLength = NumBits.IPV4;
    } else if (address instanceof Inet6Address) {
      if (this.prefixBits < 0 || this.prefixBits > NumBits.IPV6) {
        throw new IllegalArgumentException(
            String.format("IPv6 prefix %d is out of range", this.prefixBits));
      }
      ipLength = NumBits.IPV6;
    } else {
      throw new IllegalArgumentException(
          String.format("InetAddress %s is neither IPv4 nor IPv6", address));
    }
  }

  /**
   * Parses CIDR notation and returns the ip and prefix as a pair, or null if the input doesn't
   * match CIDR regex.
   */
  @Nullable
  private static Pair<String, Integer> parse(String cidr) {
    final Matcher matcher = CIDR_REGEX.matcher(cidr);
    if (matcher.matches()) {
      String ip = matcher.group(1);
      int prefixLen = Integer.parseInt(matcher.group(2));
      return Pair.create(ip, prefixLen);
    }
    return null;
  }

  /**
   * Creates Cidr from a CIDR notation string.
   *
   * @throws IllegalArgumentException if {@code cidr} is invalid
   */
  public static Cidr parseFrom(String cidr) {
    Pair<String, Integer> parsedCidr = parse(cidr);
    if (parsedCidr == null) {
      throw new IllegalArgumentException(String.format("Invalid CIDR %s", cidr));
    }
    InetAddress ia;
    try {
      ia = InetAddress.getByName(parsedCidr.first);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(String.format("Invalid IP address %s", parsedCidr.first));
    }
    return new Cidr(ia, parsedCidr.second);
  }

  /**
   * Returns the InetAddress corresponding to both the network and host portions of the CIDR.
   *
   * <p>For example, for "192.168.1.100/24" this would return "192.168.1.100".
   */
  public InetAddress getInetAddress() {
    return NetMath.inetAddressFromBigInteger(ipBits, ipLength);
  }

  /**
   * Returns the Cidr corresponding to the network portion of the CIDR.
   *
   * <p>For example, for "192.168.1.100/24" this would return "192.168.1.0/24".
   */
  public Cidr networkOnly() {
    BigInteger mask = BigInteger.ONE.shiftLeft(ipLength - prefixBits).subtract(BigInteger.ONE);
    InetAddress network = NetMath.inetAddressFromBigInteger(ipBits.andNot(mask), ipLength);
    return new Cidr(network, prefixBits);
  }

  BigInteger getIpBits() {
    return ipBits;
  }

  @NumBits
  int getIpLength() {
    return ipLength;
  }

  public int getPrefixBits() {
    return prefixBits;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Cidr)) {
      return false;
    }

    Cidr cidr = (Cidr) o;
    if (ipLength != cidr.ipLength) {
      return false;
    }
    if (prefixBits != cidr.prefixBits) {
      return false;
    }
    return ipBits.equals(cidr.ipBits);
  }

  @Override
  public String toString() {
    return getInetAddress().getHostAddress() + "/" + getPrefixBits();
  }

  @Override
  public int hashCode() {
    int result = ipBits.hashCode();
    result = 31 * result + ipLength;
    result = 31 * result + prefixBits;
    return result;
  }
}
