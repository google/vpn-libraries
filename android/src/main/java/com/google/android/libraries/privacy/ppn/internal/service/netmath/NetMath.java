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

package com.google.android.libraries.privacy.ppn.internal.service.netmath;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * NetMath provides utility math functions for networking, which assumes the input parameters have
 * the same IP version.
 */
public final class NetMath {

  /**
   * Returns a minimal, sorted list of ranges in {@code outer} that are *not* in the excluded
   * ranges.
   *
   * <p>An empty list is returned if the result is an empty range.
   */
  public static List<Cidr> invert(Cidr outer, List<Cidr> exclude) {
    IpRange outerRange = new IpRange(outer);
    List<IpRange> excludeRanges = new ArrayList<>();
    for (Cidr e : exclude) {
      excludeRanges.add(new IpRange(e));
    }
    sortIpRanges(excludeRanges);

    List<IpRange> res = new ArrayList<>();
    BigInteger begin = outerRange.getLow();
    BigInteger end = outerRange.getHigh();
    int numBits = outer.getIpLength();
    for (IpRange ex : excludeRanges) {
      // Whether [begin, end] can be cut by ex, which means begin < ex.low && ex.low <= end.
      boolean canCut = begin.compareTo(ex.getLow()) < 0 && ex.getLow().compareTo(end) <= 0;
      if (canCut) {
        BigInteger newEnd = ex.getLow().subtract(BigInteger.ONE);
        res.add(new IpRange(begin, newEnd, numBits));
      }
      // Whether begin should advance to next position.
      boolean shouldAdvance = ex.getLow().compareTo(end) <= 0;
      if (shouldAdvance) {
        BigInteger newBegin = ex.getHigh().add(BigInteger.ONE);
        begin = max(begin, newBegin);
      }
      if (begin.compareTo(end) > 0) {
        // There's nothing left.
        break;
      }
    }
    if (begin.compareTo(end) <= 0) {
      res.add(new IpRange(begin, end, numBits));
    }
    return toCidrs(res);
  }

  /** Sorts the given ip ranges in place. */
  private static void sortIpRanges(List<IpRange> ranges) {
    Collections.sort(
        ranges,
        new Comparator<IpRange>() {
          @Override
          public int compare(IpRange a, IpRange b) {
            int diff = a.getLow().compareTo(b.getLow());
            if (diff != 0) {
              return diff;
            }
            return a.getHigh().compareTo(b.getHigh());
          }
        });
  }

  /** Returns a list of CIDR notations that covers the same set of IPs as the input ranges. */
  static List<Cidr> toCidrs(List<IpRange> ipRanges) {
    List<Cidr> res = new ArrayList<>();
    for (IpRange ipRange : ipRanges) {
      res.addAll(ipRange.toCidrs());
    }
    return res;
  }

  /**
   * Returns an InetAddress created from raw ip.
   *
   * @throws IllegalArgumentException when ip is out of range or numBits is neither IPv4 or IPv6
   */
  static InetAddress inetAddressFromBigInteger(BigInteger ip, @IpRange.NumBits int numBits) {
    if (numBits != IpRange.NumBits.IPV4 && numBits != IpRange.NumBits.IPV6) {
      throw new IllegalArgumentException(
          String.format("NumBits %d is neither IPv4 nor IPv6", numBits));
    }
    BigInteger ipBoundary = BigInteger.ONE.shiftLeft(numBits);
    if (ip.compareTo(BigInteger.ZERO) < 0 || ip.compareTo(ipBoundary) >= 0) {
      throw new IllegalArgumentException(
          String.format(
              "IP %s is out of %s range", ip, numBits == IpRange.NumBits.IPV4 ? "IPv4" : "IPv6"));
    }

    int targetBytes = numBits / 8;
    byte[] from = ip.toByteArray();
    byte[] to;
    if (from.length == targetBytes) {
      to = from;
    } else {
      // The length of rawBytes can be greater than targetSize, e.g. "255.255.255.255" stores
      // as [0, 0xff, 0xff, 0xff, 0xff]. Or it can be smaller, e.g. "0.0.0.1" stores as [1].
      to = new byte[targetBytes];
      for (int i = to.length - 1, j = from.length - 1; i >= 0 && j >= 0; i--, j--) {
        to[i] = from[j];
      }
    }
    try {
      return InetAddress.getByAddress(to);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(
          String.format(
              "Unable to create InetAddress from %s, which should never happen",
              Arrays.toString(to)),
          e);
    }
  }

  private static BigInteger max(BigInteger a, BigInteger b) {
    if (a.compareTo(b) >= 0) {
      return a;
    }
    return b;
  }
}
