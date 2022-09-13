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

#include "privacy/net/krypton/utils/proto_comparison.h"

#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(ProtoComparison, IpRangeEquiv) {
  TunFdData_IpRange ipr1, ipr2;

  // IP family
  ipr1.set_ip_family(TunFdData::IpRange::IPV4);
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr1), IsTrue());
  ipr2.set_ip_family(TunFdData::IpRange::IPV6);
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr2), IsFalse());

  // IP range
  ipr1.set_ip_range("foo");
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr1), IsTrue());
  ipr2 = ipr1;
  ipr2.set_ip_range("bar");
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr2), IsFalse());

  // IP prefix
  ipr1.set_prefix(100);
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr1), IsTrue());
  ipr2 = ipr1;
  ipr2.set_prefix(200);
  EXPECT_THAT(IpRangeEquiv(ipr1, ipr2), IsFalse());
}

TEST(ProtoComparison, TunFdDataEquiv) {
  TunFdData td1, td2;
  TunFdData_IpRange ipr1, ipr2;

  // Session name
  td1.set_session_name("foobar");
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());
  td2.set_session_name("barfoo");
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // MTU
  td1.set_mtu(1000);
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());
  td2 = td1;
  td2.set_mtu(2000);
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // is_metered
  td1.set_is_metered(true);
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  td2 = td1;
  td2.set_is_metered(false);
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // send_buffer_size
  td1.set_send_buffer_size(1000);
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  td2 = td1;
  td2.set_send_buffer_size(2000);
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // receive_buffer_size
  td1.set_receive_buffer_size(1000);
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  td2 = td1;
  td2.set_receive_buffer_size(2000);
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // tunnel_ip_addresses
  ipr1.set_ip_family(TunFdData::IpRange::IPV4);
  *td1.add_tunnel_ip_addresses() = ipr1;
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  td2 = td1;
  ipr2.set_ip_family(TunFdData::IpRange::IPV6);
  *td2.add_tunnel_ip_addresses() = ipr2;
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());

  // tunnel_dns_addresses
  *td1.add_tunnel_dns_addresses() = ipr1;
  EXPECT_THAT(TunFdDataEquiv(td1, td1), IsTrue());
  td2 = td1;
  *td2.add_tunnel_dns_addresses() = ipr2;
  EXPECT_THAT(TunFdDataEquiv(td1, td2), IsFalse());
}

}  // namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
