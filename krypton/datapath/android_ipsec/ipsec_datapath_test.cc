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

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/test_packet_pipe.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

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

class MockIpSecVpnService : public IpSecDatapath::IpSecVpnServiceInterface {
 public:
  MOCK_METHOD(DatapathInterface *, BuildDatapath,
              (const KryptonConfig &, utils::LooperThread *,
               TimerManager *timer_manager),
              (override));

  MOCK_METHOD(absl::StatusOr<std::unique_ptr<PacketPipe>>, CreateNetworkPipe,
              (const NetworkInfo &, const Endpoint &), (override));

  MOCK_METHOD(absl::Status, CreateTunnel, (const TunFdData &), (override));

  MOCK_METHOD(PacketPipe *, GetTunnel, (), (override));

  MOCK_METHOD(void, CloseTunnel, (), (override));

  MOCK_METHOD(absl::Status, ConfigureIpSec, (const IpSecTransformParams &),
              (override));
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

    tunnel_.Close();
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
  }

  void WaitForNotifications() {
    absl::Mutex lock;
    absl::CondVar condition;
    absl::MutexLock l(&lock);
    looper_.Post([&lock, &condition] {
      absl::MutexLock l(&lock);
      condition.SignalAll();
    });
    condition.Wait(&lock);
  }

  AddEgressResponse fake_add_egress_response_;
  utils::LooperThread looper_{"Krypton Looper"};
  IpSecDatapath datapath_{&looper_, &vpn_service_};
  NetworkInfo network_info_;
  MockIpSecVpnService vpn_service_;
  MockNotification notification_;
  TestPacketPipe tunnel_{1002};
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
  auto pipe_ptr = std::make_unique<TestPacketPipe>(30);
  auto pipe = pipe_ptr.get();
  EXPECT_CALL(vpn_service_, CreateNetworkPipe(_, _))
      .WillOnce(::testing::Return(testing::ByMove(std::move(pipe_ptr))));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  // add the FD information of network & tunnel.
  params_.mutable_ipsec()->set_network_id(100);
  params_.mutable_ipsec()->set_network_fd(30);
  EXPECT_CALL(vpn_service_,
              ConfigureIpSec(testing::EqualsProto(params_.ipsec())));

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_.SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(notification_, DatapathEstablished);
  Packet packet("foo", 3, IPProtocol::kIPv4, [] {});
  std::vector<Packet> packets;
  packets.emplace_back(std::move(packet));
  ASSERT_OK_AND_ASSIGN(auto handler, pipe->GetReadHandler());
  EXPECT_TRUE(handler(absl::OkStatus(), std::move(packets)));
  WaitForNotifications();

  datapath_.Stop();
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
