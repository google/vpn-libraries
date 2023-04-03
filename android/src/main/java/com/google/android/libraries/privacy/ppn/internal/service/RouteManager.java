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

package com.google.android.libraries.privacy.ppn.internal.service;

import android.net.VpnService;
import com.google.android.libraries.privacy.ppn.internal.service.netmath.Cidr;
import com.google.android.libraries.privacy.ppn.internal.service.netmath.NetMath;
import java.util.ArrayList;
import java.util.List;

/** Manages the routes that are included in the VPN. */
public class RouteManager {

  private RouteManager() {}

  /** Uses a standard set of IPs to build the list of IPv4 routes to include in PPN. */
  public static void addIpv4Routes(VpnService.Builder builder) {
    List<Cidr> ipv4SubnetsToExclude = new ArrayList<>();

    // IPv4
    // See
    // https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    // for the list of these addresses.
    ipv4SubnetsToExclude.add(Cidr.parseFrom("0.0.0.0/8"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("10.0.0.0/8"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("100.64.0.0/10"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("127.0.0.0/8"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("169.254.0.0/16"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("172.16.0.0/12"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("192.0.0.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("192.0.2.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("192.88.99.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("192.168.0.0/16"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("198.18.0.0/15"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("198.51.100.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("203.0.113.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("224.0.0.0/24"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("239.255.255.250/32"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("240.0.0.0/4"));
    ipv4SubnetsToExclude.add(Cidr.parseFrom("255.255.255.255/32"));

    List<Cidr> includeIpv4 = NetMath.invert(Cidr.parseFrom("0.0.0.0/0"), ipv4SubnetsToExclude);
    for (Cidr cidr : includeIpv4) {
      builder.addRoute(cidr.getInetAddress().getHostAddress(), cidr.getPrefixBits());
    }
  }

  /** Uses a standard set of IPs to build the list of IPv6 routes to include in PPN. */
  public static void addIpv6Routes(VpnService.Builder builder) {
    List<Cidr> ipv6SubnetsToExclude = new ArrayList<>();

    // IPv6
    // See
    // https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    // for the list of these addresses.
    ipv6SubnetsToExclude.add(Cidr.parseFrom("::1/128"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("::/128"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("64:ff9b:1::/48"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("100::/64"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("2001::/23"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("2001:2::/48"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("2001:db8::/32"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("2002::/16"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("fc00::/7"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("fe80::/10"));
    ipv6SubnetsToExclude.add(Cidr.parseFrom("ff00::/8"));
    List<Cidr> includeIpv6 = NetMath.invert(Cidr.parseFrom("::/0"), ipv6SubnetsToExclude);
    for (Cidr cidr : includeIpv6) {
      builder.addRoute(cidr.getInetAddress().getHostAddress(), cidr.getPrefixBits());
    }
  }
}
