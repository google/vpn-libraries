// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/endpoint.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>

#include "privacy/net/krypton/pal/packet.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {

TEST(EndpointTest, TestIPV4Endpoint) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("192.168.0.1:2153"));
  EXPECT_EQ(endpoint.address(), "192.168.0.1");
  EXPECT_EQ(endpoint.port(), 2153);
  EXPECT_EQ(endpoint.ToString(), "192.168.0.1:2153");
  EXPECT_EQ(endpoint.ip_protocol(), IPProtocol::kIPv4);
}

TEST(EndpointTest, TestIPV6Endpoint) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("[2604:ca00:f004:3::5]:2153"));
  EXPECT_EQ(endpoint.address(), "2604:ca00:f004:3::5");
  EXPECT_EQ(endpoint.port(), 2153);
  EXPECT_EQ(endpoint.ToString(), "[2604:ca00:f004:3::5]:2153");
  EXPECT_EQ(endpoint.ip_protocol(), IPProtocol::kIPv6);
}

TEST(EndpointTest, TestEqual) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint1,
                       GetEndpointFromHostPort("192.168.0.1:2153"));
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint2,
                       GetEndpointFromHostPort("192.168.0.1:2153"));
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint3,
                       GetEndpointFromHostPort("192.168.0.1:2152"));
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint4,
                       GetEndpointFromHostPort("[2604:ca00:f004:3::5]:2153"));
  EXPECT_EQ(endpoint1, endpoint2);
  EXPECT_NE(endpoint1, endpoint3);
  EXPECT_NE(endpoint1, endpoint4);
}

TEST(EndpointTest, TestGetSockAddrWithIpv4Addr) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("192.168.0.1:2153"));

  ASSERT_OK_AND_ASSIGN(auto sockaddr, endpoint.GetSockAddr());

  auto* ipv4_sockaddr = reinterpret_cast<sockaddr_in*>(&sockaddr.sockaddr);
  EXPECT_EQ(ipv4_sockaddr->sin_family, AF_INET);
  EXPECT_EQ(ipv4_sockaddr->sin_port, htons(2153));
  in_addr expected_addr;
  inet_pton(AF_INET, "192.168.0.1", &expected_addr);
  EXPECT_EQ(ipv4_sockaddr->sin_addr.s_addr, expected_addr.s_addr);
}

TEST(EndpointTest, TestGetSockAddrWithIpv6Addr) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("[2604:ca00:f004:3::5]:2153"));

  ASSERT_OK_AND_ASSIGN(auto sockaddr, endpoint.GetSockAddr());

  auto* ipv6_sockaddr = reinterpret_cast<sockaddr_in6*>(&sockaddr.sockaddr);
  EXPECT_EQ(ipv6_sockaddr->sin6_family, AF_INET6);
  EXPECT_EQ(ipv6_sockaddr->sin6_port, htons(2153));
  in6_addr expected_addr;
  inet_pton(AF_INET6, "2604:ca00:f004:3::5", &expected_addr);
  EXPECT_EQ(memcmp(ipv6_sockaddr->sin6_addr.s6_addr, expected_addr.s6_addr,
                   sizeof(expected_addr.s6_addr)),
            0);
}

TEST(EndpointTest, TestGetSockAddrV6OnlyWithIpv4Addr) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("192.168.0.1:2153"));

  ASSERT_OK_AND_ASSIGN(auto sockaddr, endpoint.GetSockAddrV6Only());

  auto* ipv6_sockaddr = reinterpret_cast<sockaddr_in6*>(&sockaddr.sockaddr);
  EXPECT_EQ(ipv6_sockaddr->sin6_family, AF_INET6);
  EXPECT_EQ(ipv6_sockaddr->sin6_port, htons(2153));
  in_addr expected_ipv4_addr;
  inet_pton(AF_INET, "192.168.0.1", &expected_ipv4_addr);
  in6_addr expected_ipv6_addr;
  expected_ipv6_addr.s6_addr32[0] = 0x00000000;
  expected_ipv6_addr.s6_addr32[1] = 0x00000000;
  expected_ipv6_addr.s6_addr32[2] = htonl(0x0000FFFF);
  expected_ipv6_addr.s6_addr32[3] = expected_ipv4_addr.s_addr;
  EXPECT_EQ(
      memcmp(&ipv6_sockaddr->sin6_addr, &expected_ipv6_addr, sizeof(in6_addr)),
      0);
}

TEST(EndpointTest, TestGetSockAddrV6OnlyWithIpv6Addr) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("[2604:ca00:f004:3::5]:2153"));

  ASSERT_OK_AND_ASSIGN(auto sockaddr, endpoint.GetSockAddrV6Only());

  auto* ipv6_sockaddr = reinterpret_cast<sockaddr_in6*>(&sockaddr.sockaddr);
  EXPECT_EQ(ipv6_sockaddr->sin6_family, AF_INET6);
  EXPECT_EQ(ipv6_sockaddr->sin6_port, htons(2153));
  in6_addr expected_addr;
  inet_pton(AF_INET6, "2604:ca00:f004:3::5", &expected_addr);
  EXPECT_EQ(memcmp(ipv6_sockaddr->sin6_addr.s6_addr, expected_addr.s6_addr,
                   sizeof(expected_addr.s6_addr)),
            0);
}

}  // namespace krypton
}  // namespace privacy
