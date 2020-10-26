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

import androidx.annotation.IntDef;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

/**
 * An immutable contiguous range of IP addresses from low to high.
 *
 * <p>Both low and high are inclusive. The range cannot be empty. The IP version can be either v4 or
 * v6.
 */
public class IpRange {

  @Retention(RetentionPolicy.SOURCE)
  @IntDef({NumBits.IPV4, NumBits.IPV6})
  @interface NumBits {
    int IPV4 = 32;
    int IPV6 = 128;
  }

  private final BigInteger low;
  private final BigInteger high;
  private final @NumBits int numBits;

  IpRange(BigInteger low, BigInteger high, @NumBits int numBits) {
    if (numBits != NumBits.IPV4 && numBits != NumBits.IPV6) {
      throw new IllegalArgumentException(
          String.format("NumBits %d is neither IPv4 nor IPv6", numBits));
    }
    BigInteger ipBoundary = BigInteger.ONE.shiftLeft(numBits);
    if (low.compareTo(BigInteger.ZERO) < 0 || low.compareTo(ipBoundary) >= 0) {
      throw new IllegalArgumentException(
          String.format(
              "Low %s is out of %s range", low, numBits == NumBits.IPV4 ? "IPv4" : "IPv6"));
    }
    if (high.compareTo(BigInteger.ZERO) < 0 || high.compareTo(ipBoundary) >= 0) {
      throw new IllegalArgumentException(
          String.format(
              "High %s is out of %s range", high, numBits == NumBits.IPV4 ? "IPv4" : "IPv6"));
    }
    this.low = low;
    this.high = high;
    this.numBits = numBits;
  }

  private IpRange(BigInteger ip, @NumBits int numBits, int prefixBits) {
    this.numBits = numBits;
    BigInteger full = BigInteger.ONE.shiftLeft(this.numBits);
    // Calculate mask = (1 << numBits) - (1 << (numBits - prefix)), e.g. the mask of IPv4 prefix
    // "/24" is "255.255.255.0".
    BigInteger mask = full.subtract(BigInteger.ONE.shiftLeft(this.numBits - prefixBits));
    low = ip.and(mask);
    // Calculate invMask = mask ^ (full - 1), e.g. the inverse mask of above example is
    // "0.0.0.255".
    BigInteger invMask = mask.xor(full.subtract(BigInteger.ONE));
    high = ip.or(invMask);
  }

  public IpRange(Cidr cidr) {
    this(cidr.getIpBits(), cidr.getIpLength(), cidr.getPrefixBits());
  }

  /** Returns a minimal list of CIDR notation strings that represent this IP range. */
  List<Cidr> toCidrs() {
    List<Cidr> res = new ArrayList<>();
    // Queue of CIDRs.
    Queue<Cidr> q = new LinkedList<>();
    q.add(new Cidr(BigInteger.ZERO, numBits, 0));
    while (!q.isEmpty()) {
      Cidr cidr = q.poll();
      IpRange r = new IpRange(cidr.getIpBits(), numBits, cidr.getPrefixBits());
      if (contains(r)) {
        res.add(cidr);
        continue;
      }
      if (cidr.getPrefixBits() >= numBits) {
        // No more range that is smaller than r.
        continue;
      }
      if (!overlaps(r)) {
        continue;
      }
      q.add(new Cidr(cidr.getIpBits(), numBits, cidr.getPrefixBits() + 1));
      BigInteger leftmost = BigInteger.ONE.shiftLeft(numBits - 1 - cidr.getPrefixBits());
      q.add(new Cidr(cidr.getIpBits().or(leftmost), numBits, cidr.getPrefixBits() + 1));
    }
    return res;
  }

  /** Returns true if the this range contains the inner range. */
  private boolean contains(IpRange inner) {
    return low.compareTo(inner.low) <= 0 && inner.high.compareTo(high) <= 0;
  }

  /** Returns true if this range overlaps with the given range. */
  private boolean overlaps(IpRange that) {
    return low.compareTo(that.high) <= 0 && that.low.compareTo(high) <= 0;
  }

  BigInteger getLow() {
    return low;
  }

  BigInteger getHigh() {
    return high;
  }

  @NumBits
  int getNumBits() {
    return numBits;
  }

  // This is useful in unit tests and state dumps, this is not auto-generated.
  @Override
  public String toString() {
    return String.format(
        "IpRange{%s, %s}",
        NetMath.inetAddressFromBigInteger(low, numBits).getHostAddress(),
        NetMath.inetAddressFromBigInteger(high, numBits).getHostAddress());
  }

  @Override
  public int hashCode() {
    int result = low.hashCode();
    result = 31 * result + high.hashCode();
    result = 31 * result + numBits;
    return result;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof IpRange)) {
      return false;
    }

    IpRange ipRange = (IpRange) o;
    if (numBits != ipRange.numBits) {
      return false;
    }
    if (!low.equals(ipRange.low)) {
      return false;
    }
    return high.equals(ipRange.high);
  }
}
