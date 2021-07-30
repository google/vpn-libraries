// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
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

#include "privacy/net/krypton/pal/packet.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {

namespace {

class EndpointTest : public ::testing::Test {};

}  // namespace

TEST_F(EndpointTest, TestIPV4Endpoint) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("192.168.0.1:2153"));
  EXPECT_EQ(endpoint.address(), "192.168.0.1");
  EXPECT_EQ(endpoint.port(), 2153);
  EXPECT_EQ(endpoint.ToString(), "192.168.0.1:2153");
  EXPECT_EQ(endpoint.ip_protocol(), IPProtocol::kIPv4);
}

TEST_F(EndpointTest, TestIPV6Endpoint) {
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint,
                       GetEndpointFromHostPort("[2604:ca00:f004:3::5]:2153"));
  EXPECT_EQ(endpoint.address(), "2604:ca00:f004:3::5");
  EXPECT_EQ(endpoint.port(), 2153);
  EXPECT_EQ(endpoint.ToString(), "[2604:ca00:f004:3::5]:2153");
  EXPECT_EQ(endpoint.ip_protocol(), IPProtocol::kIPv6);
}

TEST_F(EndpointTest, TestEqual) {
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

}  // namespace krypton
}  // namespace privacy
