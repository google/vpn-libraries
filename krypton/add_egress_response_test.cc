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

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

// TODO: Write fuzz testing of the JSON responses.
TEST(AuthAndSignResponse, TestAuthAndSignResponse) {
  AddEgressResponse add_egress_response;
  ASSERT_OK(add_egress_response.DecodeFromJsonObject(R"string(
  {
    "http": {
      "status":{
        "code": 200,
        "message" : "OK"
      }
    },
    "json_body": {
       "bridge": {
          "session_id": 1234,
          "error": "no error",
          "session_token": "A89C39",
          "client_crypto_key": "some_client_crypto_key",
          "server_crypto_key": "some_server_crypto_key",
          "ip_ranges":["10.2.2.123","fec2:0001"],
          "data_plane_sock_addrs": ["10.2.2.124","fec2:0002"],
          "control_plane_sock_addrs": ["10.2.2.125","fec2:0003"]
       }
    }
  })string"));

  ASSERT_OK(add_egress_response.bridge_dataplane_response());
  auto status_or_bridge_response =
      add_egress_response.bridge_dataplane_response();
  EXPECT_THAT(status_or_bridge_response.value()->GetSessionId(),
              ::testing::status::IsOkAndHolds(1234));
  EXPECT_THAT(status_or_bridge_response.value()->GetError(),
              ::testing::status::IsOkAndHolds("no error"));
  EXPECT_THAT(status_or_bridge_response.value()->GetSessionToken(),
              ::testing::status::IsOkAndHolds("A89C39"));
  EXPECT_THAT(status_or_bridge_response.value()->GetClientCryptoKey(),
              ::testing::status::IsOkAndHolds("some_client_crypto_key"));
  EXPECT_THAT(status_or_bridge_response.value()->GetServerCryptoKey(),
              ::testing::status::IsOkAndHolds("some_server_crypto_key"));
  EXPECT_THAT(status_or_bridge_response.value()->GetIpRanges(),
              ::testing::status::IsOkAndHolds(
                  ::testing::ElementsAre("10.2.2.123", "fec2:0001")));
  EXPECT_THAT(status_or_bridge_response.value()->GetDataplaneSockAddresses(),
              ::testing::status::IsOkAndHolds(
                  ::testing::ElementsAre("10.2.2.124", "fec2:0002")));
  EXPECT_THAT(status_or_bridge_response.value()->GetControlPlaneSockAddresses(),
              ::testing::status::IsOkAndHolds(
                  ::testing::ElementsAre("10.2.2.125", "fec2:0003")));
}

TEST(AddEgressResponse, TestAddEgressResponse) {
  AddEgressResponse add_egress_response;
  ASSERT_OK(add_egress_response.DecodeFromJsonObject(R"string(
  {
    "http": {
      "status": {
        "code": 200,
        "message": "OK"
      }
    },
    "json_body": {
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
    }

  })string"));

  ASSERT_OK(add_egress_response.ppn_dataplane_response());
  auto status_or_ppn_response = add_egress_response.ppn_dataplane_response();
  EXPECT_THAT(status_or_ppn_response.value()->GetUserPrivateIp(),
              ::testing::status::IsOkAndHolds(
                  ::testing::UnorderedElementsAre("127.0.0.1", "fe80::1")));
  EXPECT_THAT(status_or_ppn_response.value()->GetEgressPointSockAddr(),
              ::testing::status::IsOk());
  EXPECT_EQ(
      status_or_ppn_response.value()->GetEgressPointSockAddr().value().size(),
      1);
  EXPECT_THAT(
      status_or_ppn_response.value()->GetEgressPointSockAddr().value()[0],
      "addr1");
  EXPECT_THAT(status_or_ppn_response.value()->GetEgressPointPublicKey(),
              ::testing::status::IsOkAndHolds("1234567890abcdef"));
  EXPECT_THAT(status_or_ppn_response.value()->GetServerNonce(),
              ::testing::status::IsOkAndHolds("abcd"));
  EXPECT_THAT(status_or_ppn_response.value()->GetUplinkSpi(),
              ::testing::status::IsOkAndHolds(123));
  // 2020-08-07T01:06:13+00:00 == 1596762373000ms since epoch.
  absl::Time expected_time = absl::FromUnixMillis(1596762373000);
  EXPECT_THAT(status_or_ppn_response.value()->GetExpiry(),
              ::testing::status::IsOkAndHolds(expected_time));
}

}  // namespace krypton
}  // namespace privacy
