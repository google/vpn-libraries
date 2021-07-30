// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/ipsec_packet.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "privacy/net/krypton/datapath/ipsec/ipsec.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

namespace {

class IpSecPacketTest : public ::testing::Test {};

}  // namespace

TEST_F(IpSecPacketTest, TestSize) {
  IpSecPacket packet;
  EXPECT_EQ(packet.data_size(), 0);

  packet.resize_data(100);
  EXPECT_EQ(packet.data_size(), 100);

  EXPECT_DEATH(packet.resize_data(13), "");

  EXPECT_DEATH(packet.resize_data(-1), "");

  EXPECT_DEATH(packet.resize_data(kMaxIpsecDataSize + 1), "");
}

TEST_F(IpSecPacketTest, TestLayout) {
  IpSecPacket packet;

  // Put some data in the header.
  packet.header()->client_spi = 10;
  packet.header()->sequence_number = 11;
  memcpy(packet.header()->initialization_vector, "12345678", kIVLen);

  // Write a max-length string to the data section.
  std::string max(kMaxIpsecDataSize, '*');
  max.copy(packet.data(), kMaxIpsecDataSize, 0);
  packet.resize_data(kMaxIpsecDataSize);

  // Put some data in the trailer.
  packet.trailer()->integrity_check_value = 13;

  // Verify that none of the writes clobbered one another.
  EXPECT_EQ(packet.header()->client_spi, 10);
  EXPECT_EQ(packet.header()->sequence_number, 11);
  EXPECT_EQ(0,
            memcmp(packet.header()->initialization_vector, "12345678", kIVLen));
  EXPECT_EQ(packet.trailer()->integrity_check_value, 13);
  EXPECT_EQ(packet.data_size(), kMaxIpsecDataSize);
  char *data_ptr = packet.data();
  for (int i = 0; i < kMaxIpsecDataSize; i++) {
    EXPECT_EQ(*data_ptr, '*');
    data_ptr++;
  }

  // Verify the overall packet.
  EXPECT_EQ(sizeof(EspHeader) + kMaxIpsecDataSize + sizeof(EspTrailer),
            packet.buffer_size());
  EXPECT_EQ(reinterpret_cast<const char *>(packet.header()), packet.buffer());
}

TEST_F(IpSecPacketTest, TestGetIPV4Protocol) {
  in_addr ip_src;
  inet_pton(AF_INET, "192.168.0.1", &ip_src);
  in_addr ip_dst;
  inet_pton(AF_INET, "192.168.0.2", &ip_dst);

  // Create an IPV4 header.
  ip ip_hdr = {};
  ip_hdr.ip_v = 4;
  ip_hdr.ip_hl = sizeof(ip) / 4;
  ip_hdr.ip_off = 0;
  ip_hdr.ip_p = IPPROTO_UDP;
  ip_hdr.ip_src = ip_src;
  ip_hdr.ip_dst = ip_dst;

  IpSecPacket packet;

  // Insert IP header into the packet.
  memcpy(packet.data(), &ip_hdr, sizeof(ip_hdr));
  packet.resize_data(sizeof(ip_hdr));

  // Verify IP protocol is parsed correctly.
  EXPECT_EQ(packet.GetIPProtocol(), IPProtocol::kIPv4);
}

TEST_F(IpSecPacketTest, TestGetIPV6Protocol) {
  in6_addr ip_src;
  inet_pton(AF_INET6, "abcd::", &ip_src);
  in6_addr ip_dst;
  inet_pton(AF_INET6, "1234::", &ip_dst);

  // Create an IPV6 header.
  ip6_hdr ip_hdr = {};
  ip_hdr.ip6_vfc = 6 << 4;
  ip_hdr.ip6_nxt = IPPROTO_UDP;
  ip_hdr.ip6_src = ip_src;
  ip_hdr.ip6_dst = ip_dst;

  IpSecPacket packet;

  // Insert IP header into the packet.
  memcpy(packet.data(), &ip_hdr, sizeof(ip_hdr));
  packet.resize_data(sizeof(ip_hdr));

  // Verify IP protocol is parsed correctly.
  EXPECT_EQ(packet.GetIPProtocol(), IPProtocol::kIPv6);
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
