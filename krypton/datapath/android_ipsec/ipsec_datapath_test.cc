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

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"

#include <memory>
#include <utility>
#include <vector>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_ipsec_socket.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_ipsec_vpn_service.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_tunnel.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::status::StatusIs;

class MockNotification : public DatapathInterface::NotificationInterface {
 public:
  MOCK_METHOD(void, DatapathEstablished, (), (override));
  MOCK_METHOD(void, DatapathFailed, (const absl::Status &), (override));
  MOCK_METHOD(void, DatapathPermanentFailure, (const absl::Status &),
              (override));
  MOCK_METHOD(void, DoRekey, (), (override));
};

class IpSecDatapathTest : public ::testing::Test {
 public:
  IpSecDatapathTest() { datapath_.RegisterNotificationHandler(&notification_); }

  ~IpSecDatapathTest() override {
    // We need to explicitly stop the thread and join it before we destroy the
    // other class members, or else queued up runnables may reference members
    // after they are destroyed. But we don't want to destroy the thread yet,
    // because other members may still try to put stuff on it.
    looper_.Stop();
    looper_.Join();

    PPN_LOG_IF_ERROR(tunnel_.Close());
  }

  void SetUp() override {
    HttpResponse fake_add_egress_http_response;
    fake_add_egress_http_response.mutable_status()->set_code(200);
    fake_add_egress_http_response.mutable_status()->set_message("OK");
    fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["192.0.2.0:8080", "[2604:ca00:f001:4::5]:2153"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 1234,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })string");

    auto fake_add_egress_response =
        AddEgressResponse::FromProto(fake_add_egress_http_response);
    ASSERT_OK(fake_add_egress_response);
    fake_add_egress_response_ = *fake_add_egress_response;

    // Set the default network_info.
    network_info_.set_network_id(100);
    network_info_.set_network_type(NetworkType::CELLULAR);

    // IpSec Params
    auto *params = params_.mutable_ipsec();
    params->set_destination_address("192.0.2.0");
    params->set_destination_address_family(NetworkInfo::V4);
    params->set_destination_port(8080);
    params->set_downlink_spi(1);
    params->set_uplink_spi(1234);
    params->set_uplink_key("uplink_key_bytes");
    params->set_downlink_key("downlink_key_bytes");
    params->set_network_id(100);
    params->set_network_fd(1);
  }

  AddEgressResponse fake_add_egress_response_;
  utils::LooperThread looper_{"Krypton Looper"};
  KryptonConfig config_;
  IpSecDatapath datapath_{config_, &looper_, &vpn_service_};
  NetworkInfo network_info_;
  MockIpSecVpnService vpn_service_;
  MockNotification notification_;
  MockTunnel tunnel_;
  TransformParams params_;
  Endpoint endpoint_{"192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4};
};

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoNetworkSocket) {
  EXPECT_THAT(datapath_.SwitchNetwork(1234, endpoint_, std::nullopt, 1),
              StatusIs(util::error::INVALID_ARGUMENT,
                       testing::HasSubstr("network_info")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoTunnelSocket) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(nullptr));
  EXPECT_THAT(datapath_.SwitchNetwork(1234, endpoint_, network_info_, 1),
              StatusIs(util::error::INVALID_ARGUMENT,
                       testing::HasSubstr("tunnel is null")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkAndNoKeyMaterial) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  //  Set KeyMaterial but not of type Ipsec.
  EXPECT_THAT(datapath_.SwitchNetwork(1234, endpoint_, network_info_, 1),
              StatusIs(util::error::FAILED_PRECONDITION,
                       testing::HasSubstr("Key Material")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkHappyPath) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _))
      .Times(1)
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_,
              ConfigureIpSec(testing::EqualsProto(params_.ipsec())));

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});

  absl::Notification established;
  absl::Notification socket_closed;
  absl::Notification tunnel_closed;

  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce(testing::Return(std::move(packets)))
      .WillOnce([&socket_closed]() {
        socket_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Closed by both the packet forwarder and the datapath.
  EXPECT_CALL(*socket, CancelReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(*socket, Close()).WillOnce(Return(absl::OkStatus()));

  EXPECT_CALL(tunnel_, ReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_.SwitchNetwork(1234, endpoint_, network_info_, 1));

  EXPECT_TRUE(
      established.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  datapath_.Stop();
}
TEST_F(IpSecDatapathTest, SwitchNetworkBadNetworkSocket) {
  // create failure to create network socket.
  EXPECT_CALL(notification_, DatapathFailed).Times(1);
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _))
      .Times(1)
      .WillOnce(Return(absl::InternalError("Failure")));

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_.SwitchNetwork(1234, endpoint_, network_info_, 1));

  datapath_.Stop();
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
