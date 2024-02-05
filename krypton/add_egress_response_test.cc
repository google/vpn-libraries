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

#include "privacy/net/krypton/add_egress_response.h"

#include "google/protobuf/timestamp.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {

using ::privacy::net::common::proto::PpnDataplaneResponse;
using ::testing::EqualsProto;
using ::testing::status::StatusIs;

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
        "addr1",
        "addr2"
      ],
      "egress_point_public_value": "MTIzNDU2Nzg5MGFiY2RlZg==",
      "server_nonce": "YWJjZA==",
      "uplink_spi": 123,
      "expiry": "2020-08-07T01:06:13+00:00",
      "mss_detection_sock_addr": [
        "addr2"
      ],
      "transport_mode_server_port": 567,
      "control_plane_addr": "test"
    }
  })string");

  ASSERT_OK_AND_ASSIGN(AddEgressResponse add_egress_response,
                       AddEgressResponse::FromProto(proto));
  ASSERT_OK_AND_ASSIGN(PpnDataplaneResponse ppn_response,
                       add_egress_response.ppn_dataplane_response());

  // For the value of expiry, 2020-08-07T01:06:13+00:00 == 1596762373s since
  // epoch.
  EXPECT_THAT(ppn_response, EqualsProto(R"pb(
                user_private_ip: { ipv4_range: "127.0.0.1" },
                user_private_ip: { ipv6_range: "fe80::1" },
                egress_point_sock_addr: "addr1",
                egress_point_sock_addr: "addr2",
                egress_point_public_value: "1234567890abcdef",
                server_nonce: "abcd",
                uplink_spi: 123,
                expiry: { seconds: 1596762373 nanos: 0 },
                mss_detection_sock_addr: "addr2",
                transport_mode_server_port: 567,
                control_plane_addr: "test",
              )pb"));
}

TEST(AddEgressResponse, TestAddEgressIkeResponse) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string(
  {
    "ike": {
      "client_id": "Zm9v",
      "shared_secret": "YmFy",
      "server_address": "127.0.0.1"
    }
  })string");

  ASSERT_OK_AND_ASSIGN(auto add_egress_response,
                       AddEgressResponse::FromProto(proto));
  ASSERT_OK_AND_ASSIGN(auto ike_response, add_egress_response.ike_response());

  EXPECT_THAT(ike_response, EqualsProto(R"pb(
                client_id: "foo"
                shared_secret: "bar"
                server_address: "127.0.0.1"
              )pb"));
}

TEST(AddEgressResponse, TestAddEgressMalformedJsonBody) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string(
  {}})string");

  EXPECT_THAT(AddEgressResponse::FromProto(proto),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace krypton
}  // namespace privacy
