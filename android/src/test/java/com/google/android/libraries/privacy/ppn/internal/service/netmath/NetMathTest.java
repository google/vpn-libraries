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

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/**
 * Unit test for {@link NetMath}.
 */
@RunWith(RobolectricTestRunner.class)
public class NetMathTest {

  @Test
  public void invert() {
    // Test data structure: outer ip range, ip ranges to exclude, expected output.
    Object[][] tests = {
      {
        Cidr.parseFrom("0.0.0.0/0"),
        new Cidr[] {Cidr.parseFrom("10.0.0.0/8")},
        new Cidr[] {
          Cidr.parseFrom("0.0.0.0/5"),
          Cidr.parseFrom("8.0.0.0/7"),
          Cidr.parseFrom("128.0.0.0/1"),
          Cidr.parseFrom("64.0.0.0/2"),
          Cidr.parseFrom("32.0.0.0/3"),
          Cidr.parseFrom("16.0.0.0/4"),
          Cidr.parseFrom("12.0.0.0/6"),
          Cidr.parseFrom("11.0.0.0/8")
        }
      },
      {
        Cidr.parseFrom("0.0.0.0/0"),
        new Cidr[] {
          Cidr.parseFrom("10.0.0.0/8"),
          Cidr.parseFrom("172.16.0.0/12"),
          Cidr.parseFrom("192.168.0.0/16"),
          Cidr.parseFrom("169.254.0.0/16"),
          Cidr.parseFrom("224.0.0.0/3")
        },
        new Cidr[] {
          Cidr.parseFrom("0.0.0.0/5"),
          Cidr.parseFrom("8.0.0.0/7"),
          Cidr.parseFrom("64.0.0.0/2"),
          Cidr.parseFrom("32.0.0.0/3"),
          Cidr.parseFrom("128.0.0.0/3"),
          Cidr.parseFrom("16.0.0.0/4"),
          Cidr.parseFrom("160.0.0.0/5"),
          Cidr.parseFrom("12.0.0.0/6"),
          Cidr.parseFrom("11.0.0.0/8"),
          Cidr.parseFrom("168.0.0.0/8"),
          Cidr.parseFrom("169.0.0.0/9"),
          Cidr.parseFrom("169.128.0.0/10"),
          Cidr.parseFrom("169.192.0.0/11"),
          Cidr.parseFrom("169.224.0.0/12"),
          Cidr.parseFrom("169.240.0.0/13"),
          Cidr.parseFrom("169.248.0.0/14"),
          Cidr.parseFrom("169.252.0.0/15"),
          Cidr.parseFrom("170.0.0.0/7"),
          Cidr.parseFrom("172.0.0.0/12"),
          Cidr.parseFrom("169.255.0.0/16"),
          Cidr.parseFrom("176.0.0.0/4"),
          Cidr.parseFrom("174.0.0.0/7"),
          Cidr.parseFrom("173.0.0.0/8"),
          Cidr.parseFrom("172.128.0.0/9"),
          Cidr.parseFrom("192.0.0.0/9"),
          Cidr.parseFrom("172.64.0.0/10"),
          Cidr.parseFrom("172.32.0.0/11"),
          Cidr.parseFrom("192.128.0.0/11"),
          Cidr.parseFrom("192.160.0.0/13"),
          Cidr.parseFrom("208.0.0.0/4"),
          Cidr.parseFrom("200.0.0.0/5"),
          Cidr.parseFrom("196.0.0.0/6"),
          Cidr.parseFrom("194.0.0.0/7"),
          Cidr.parseFrom("193.0.0.0/8"),
          Cidr.parseFrom("192.192.0.0/10"),
          Cidr.parseFrom("192.176.0.0/12"),
          Cidr.parseFrom("192.172.0.0/14"),
          Cidr.parseFrom("192.170.0.0/15"),
          Cidr.parseFrom("192.169.0.0/16"),
        }
      },
      {
        Cidr.parseFrom("::/0"),
        new Cidr[] {Cidr.parseFrom("fc00::/7")},
        new Cidr[] {
          Cidr.parseFrom("::/1"),
          Cidr.parseFrom("8000::/2"),
          Cidr.parseFrom("c000::/3"),
          Cidr.parseFrom("e000::/4"),
          Cidr.parseFrom("f000::/5"),
          Cidr.parseFrom("f800::/6"),
          Cidr.parseFrom("fe00::/7")
        }
      },
      {
        Cidr.parseFrom("::/0"),
        new Cidr[] {
          Cidr.parseFrom("fc00::/7"), Cidr.parseFrom("fe80::/10"), Cidr.parseFrom("ff00::/8")
        },
        new Cidr[] {
          Cidr.parseFrom("::/1"),
          Cidr.parseFrom("8000::/2"),
          Cidr.parseFrom("c000::/3"),
          Cidr.parseFrom("e000::/4"),
          Cidr.parseFrom("f000::/5"),
          Cidr.parseFrom("f800::/6"),
          Cidr.parseFrom("fe00::/9"),
          Cidr.parseFrom("fec0::/10"),
        }
      },
    };
    for (Object[] test : tests) {
      Cidr outer = (Cidr) test[0];
      List<Cidr> exclude = Arrays.asList((Cidr[]) test[1]);
      List<Cidr> want = Arrays.asList((Cidr[]) test[2]);

      List<Cidr> got = NetMath.invert(outer, exclude);
      assertThat(got, is(want));
    }
  }

  @Test
  public void toCidrs() {
    // Test data structure: input ip ranges, expected output.
    Object[][] tests = {
      {
        new IpRange[] {ipRange("0.0.0.0", "9.255.255.255"), ipRange("11.0.0.0", "255.255.255.255")},
        new Cidr[] {
          Cidr.parseFrom("0.0.0.0/5"),
          Cidr.parseFrom("8.0.0.0/7"),
          Cidr.parseFrom("128.0.0.0/1"),
          Cidr.parseFrom("64.0.0.0/2"),
          Cidr.parseFrom("32.0.0.0/3"),
          Cidr.parseFrom("16.0.0.0/4"),
          Cidr.parseFrom("12.0.0.0/6"),
          Cidr.parseFrom("11.0.0.0/8"),
        }
      },
      {
        new IpRange[] {
          ipRange("::", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
          ipRange("fe00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        },
        new Cidr[] {
          Cidr.parseFrom("0:0:0:0:0:0:0:0/1"),
          Cidr.parseFrom("8000:0:0:0:0:0:0:0/2"),
          Cidr.parseFrom("c000:0:0:0:0:0:0:0/3"),
          Cidr.parseFrom("e000:0:0:0:0:0:0:0/4"),
          Cidr.parseFrom("f000:0:0:0:0:0:0:0/5"),
          Cidr.parseFrom("f800:0:0:0:0:0:0:0/6"),
          Cidr.parseFrom("fe00:0:0:0:0:0:0:0/7"),
        }
      },
    };
    for (Object[] test : tests) {
      List<IpRange> input = Arrays.asList((IpRange[]) test[0]);
      List<Cidr> want = Arrays.asList((Cidr[]) test[1]);

      List<Cidr> got = NetMath.toCidrs(input);
      assertThat(got, is(want));
    }
  }

  @Test
  public void inetAddressFromBigInteger() throws UnknownHostException {
    // Test data structure: input ip, number of bits, expected output.
    Object[][] tests = {
      {ip("2.3.4.5"), IpRange.NumBits.IPV4, "2.3.4.5"},
      {ip("0.0.0.0"), IpRange.NumBits.IPV4, "0.0.0.0"},
      {
        ip("2620:0:1234:5711:e8e5:9c3d:dff4:1d32"),
        IpRange.NumBits.IPV6,
        "2620:0:1234:5711:e8e5:9c3d:dff4:1d32"
      }
    };
    for (Object[] test : tests) {
      BigInteger ip = (BigInteger) test[0];
      @IpRange.NumBits int numBits = (int) test[1];
      InetAddress want = InetAddress.getByName((String) test[2]);

      InetAddress ia = NetMath.inetAddressFromBigInteger(ip, numBits);
      assertEquals(want, ia);
    }
  }

  private static IpRange ipRange(String low, String high) {
    InetAddress lowAddress = null;
    try {
      lowAddress = InetAddress.getByName(low);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(String.format("Invalid IP address %s", low), e);
    }
    InetAddress highAddress = null;
    try {
      highAddress = InetAddress.getByName(high);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(String.format("Invalid IP address %s", high), e);
    }
    @IpRange.NumBits int numBits;
    if (lowAddress instanceof Inet4Address) {
      numBits = IpRange.NumBits.IPV4;
    } else {
      numBits = IpRange.NumBits.IPV6;
    }
    return new IpRange(
        new BigInteger(1, lowAddress.getAddress()),
        new BigInteger(1, highAddress.getAddress()),
        numBits);
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
