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

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;

import com.google.android.libraries.privacy.ppn.internal.service.netmath.IpRange.NumBits;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.hamcrest.MatcherAssert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit test for {@link Cidr}. */
@RunWith(RobolectricTestRunner.class)
public class CidrTest {

  @Test
  public void fromString_valid() {
    // Test data structure: CIDR string, expected IP bits, expected IP length, expected prefix
    // bits.
    Object[][] tests = {
      {"0.2.3.4/8", ip("0.2.3.4"), NumBits.IPV4, 8},
      {"192.0.2.0/24", ip("192.0.2.0"), NumBits.IPV4, 24},
      {"3.4.5.6/1", ip("3.4.5.6"), NumBits.IPV4, 1},
      {"3.4.5.6/32", ip("3.4.5.6"), NumBits.IPV4, 32},
      {"2001:db8::/32", ip("2001:db8::"), NumBits.IPV6, 32},
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/5",
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        NumBits.IPV6,
        5
      },
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/64",
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        NumBits.IPV6,
        64
      },
      {
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32/128",
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        NumBits.IPV6,
        128
      },
    };
    for (Object[] test : tests) {
      String str = (String) test[0];
      BigInteger wantIpBits = (BigInteger) test[1];
      @NumBits int wantIpLength = (int) test[2];
      int wantPrefixBits = (int) test[3];

      Cidr cidr = Cidr.parseFrom(str);

      String message = String.format("Testing %s", cidr);
      assertEquals(message, wantIpBits, cidr.getIpBits());
      assertEquals(message, wantIpLength, cidr.getIpLength());
      assertEquals(message, wantPrefixBits, cidr.getPrefixBits());

      // IPv6 addresses don't come out nicely, so only check for IPv4
      if (str.contains(".")) {
        assertEquals(message, str, cidr.toString());
      }
    }
  }

  @Test
  public void cidrNetworkOnly() {
    MatcherAssert.assertThat(
        "ipv4", Cidr.parseFrom("1.2.3.4/8").networkOnly(), is(Cidr.parseFrom("1.0.0.0/8")));
    MatcherAssert.assertThat(
        "ipv6",
        Cidr.parseFrom("2620:0:1234:5711:e8e5:9c3d:dff4:1d32/64").networkOnly(),
        is(Cidr.parseFrom("2620:0:1234:5711::/64")));
  }

  @Test
  public void fromString_invalid() {
    // Test data structure: invalid CIDR string.
    String[] tests = {"192.0.2.0/35", "foo", "::/-1", "::abcd", "::/129"};
    for (String cidr : tests) {
      try {
        Cidr.parseFrom(cidr);
        fail("expected IllegalArgumentException");
      } catch (IllegalArgumentException e) {
        // expected
      }
    }
  }

  private static InetAddress addr(String addr) {
    try {
      return InetAddress.getByName(addr);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(String.format("Invalid IP address %s", addr), e);
    }
  }

  private static BigInteger ip(String ip) {
    return new BigInteger(1, addr(ip).getAddress());
  }
}
