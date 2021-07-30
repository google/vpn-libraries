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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import com.google.android.libraries.privacy.ppn.internal.service.netmath.IpRange.NumBits;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit test for {@link IpRange}. */
@RunWith(RobolectricTestRunner.class)
public class IpRangeTest {

  @Test
  public void createfromCIDR() {
    // Test data structure: CIDR string, expected low, expected high, expected number of bits.
    Object[][] tests = {
      {"0.2.3.4/8", ip("0.0.0.0"), ip("0.255.255.255"), NumBits.IPV4},
      {"192.0.2.0/24", ip("192.0.2.0"), ip("192.0.2.255"), NumBits.IPV4},
      {"3.4.5.6/1", ip("0.0.0.0"), ip("127.255.255.255"), NumBits.IPV4},
      {"3.4.5.6/32", ip("3.4.5.6"), ip("3.4.5.6"), NumBits.IPV4},
      {
        "2001:db8::/32",
        ip("2001:db8::"),
        ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        NumBits.IPV6
      },
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/5",
        ip("2000:0:0:0:0:0:0:0"),
        ip("27ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        NumBits.IPV6
      },
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/64",
        ip("2620:0:1234:5711:0:0:0:0"),
        ip("2620:0:1234:5711:ffff:ffff:ffff:ffff"),
        NumBits.IPV6
      },
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/128",
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        NumBits.IPV6
      },
    };
    for (Object[] test : tests) {
      String cidr = (String) test[0];
      BigInteger wantLow = (BigInteger) test[1];
      BigInteger wantHigh = (BigInteger) test[2];
      @NumBits int wantNumBits = (int) test[3];

      IpRange r = new IpRange(Cidr.parseFrom(cidr));

      String message = String.format("Testing %s", cidr);
      assertEquals(message, wantLow, r.getLow());
      assertEquals(message, wantHigh, r.getHigh());
      assertEquals(message, wantNumBits, r.getNumBits());
    }
  }

  @Test
  public void toCidrs() {
    // Test data structure: low, high, number of bits, expected Cidr.
    Object[][] tests = {
      {
        ip("192.168.1.0"),
        ip("192.168.1.255"),
        NumBits.IPV4,
        new Cidr[] {Cidr.parseFrom("192.168.1.0/24")}
      },
      {
        ip("0.0.0.0"),
        ip("0.0.0.5"),
        NumBits.IPV4,
        new Cidr[] {Cidr.parseFrom("0.0.0.0/30"), Cidr.parseFrom("0.0.0.4/31")}
      },
      {
        ip("0.0.0.0"), ip("255.255.255.255"), NumBits.IPV4, new Cidr[] {Cidr.parseFrom("0.0.0.0/0")}
      },
      {
        ip("::3"),
        ip("::16"),
        NumBits.IPV6,
        new Cidr[] {
          Cidr.parseFrom("0:0:0:0:0:0:0:8/125"),
          Cidr.parseFrom("0:0:0:0:0:0:0:4/126"),
          Cidr.parseFrom("0:0:0:0:0:0:0:10/126"),
          Cidr.parseFrom("0:0:0:0:0:0:0:14/127"),
          Cidr.parseFrom("0:0:0:0:0:0:0:3/128"),
          Cidr.parseFrom("0:0:0:0:0:0:0:16/128")
        }
      },
    };
    for (Object[] test : tests) {
      IpRange r = new IpRange((BigInteger) test[0], (BigInteger) test[1], (int) test[2]);
      Cidr[] want = (Cidr[]) test[3];

      List<Cidr> cidrs = r.toCidrs();
      assertThat(Arrays.asList(want), is(cidrs));
    }
  }

  private static BigInteger ip(String addr) {
    InetAddress ia;
    try {
      ia = InetAddress.getByName(addr);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(String.format("Invalid IP address %s", addr), e);
    }
    return new BigInteger(1, ia.getAddress());
  }
}
