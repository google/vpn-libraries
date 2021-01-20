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

#include "privacy/net/krypton/add_egress_response.h"

#include <tuple>
#include <type_traits>

#include "google/protobuf/timestamp.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

using ::testing::EqualsProto;
using ::testing::proto::Partially;

TEST(AddEgressResponse, TestAddEgressResponse) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string(
  {
    "ppn_dataplane": {
      "user_private_ip": [
        {"ipv4_range": "127.0.0.1"},
        {"ipv6_range": "fe80::1"}
      ],
      "egress_point_sock_addr": [
        "addr1"
      ],
      "egress_point_public_value": "1234567890abcdef",
      "server_nonce": "abcd",
      "uplink_spi": 123,
      "expiry": "2020-08-07T01:06:13+00:00"
    }
  })string");

  AddEgressResponse add_egress_response;
  ASSERT_OK(add_egress_response.DecodeFromProto(proto));

  ASSERT_OK(add_egress_response.ppn_dataplane_response());
  auto ppn_response = add_egress_response.ppn_dataplane_response().value();

  EXPECT_THAT(*ppn_response, EqualsProto(R"pb(
    user_private_ip: { ipv4_range: "127.0.0.1" },
    user_private_ip: { ipv6_range: "fe80::1" },
    egress_point_sock_addr: "addr1"
    egress_point_public_value: "1234567890abcdef",
    server_nonce: "abcd",
    uplink_spi: 123,
    expiry: { seconds: 1596762373 nanos: 0 }
  )pb"));

  EXPECT_THAT(ppn_response->user_private_ip(),
              ::testing::UnorderedElementsAre(
                  Partially(EqualsProto(R"pb(ipv4_range: "127.0.0.1")pb")),
                  Partially(EqualsProto(R"pb(ipv6_range: "fe80::1")pb"))));

  EXPECT_EQ(ppn_response->egress_point_sock_addr_size(), 1);
  EXPECT_EQ(ppn_response->egress_point_sock_addr(0), "addr1");
  EXPECT_EQ(ppn_response->egress_point_public_value(), "1234567890abcdef");
  EXPECT_EQ(ppn_response->server_nonce(), "abcd");
  EXPECT_EQ(ppn_response->uplink_spi(), 123);

  // 2020-08-07T01:06:13+00:00 == 1596762373s since epoch.
  EXPECT_THAT(ppn_response->expiry(), EqualsProto(R"pb(
                seconds: 1596762373
                nanos: 0
              )pb"));
}

}  // namespace krypton
}  // namespace privacy
