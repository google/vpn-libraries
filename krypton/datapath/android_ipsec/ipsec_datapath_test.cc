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

#include <unistd.h>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "google/protobuf/duration.proto.h"
#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/android_ipsec/datagram_socket.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_tunnel.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_ipsec_socket.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_ipsec_vpn_service.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_tunnel.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::_;
using ::testing::Eq;
using ::testing::EqualsProto;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::status::StatusIs;

class MockNotification : public DatapathInterface::NotificationInterface {
 public:
  MOCK_METHOD(void, DatapathEstablished, (), (override));
  MOCK_METHOD(void, DatapathFailed, (const absl::Status &), (override));
  MOCK_METHOD(void, DatapathPermanentFailure, (const absl::Status &),
              (override));
  MOCK_METHOD(void, DoRekey, (), (override));
  MOCK_METHOD(void, DoUplinkMtuUpdate, (int, int), (override));
  MOCK_METHOD(void, DoDownlinkMtuUpdate, (int), (override));
  MOCK_METHOD(void, DatapathHealthCheckStarting, (), (override));
  MOCK_METHOD(void, DatapathHealthCheckSucceeded, (), (override));
};

class IpSecDatapathTest : public ::testing::Test {
 public:
  IpSecDatapathTest() {
    config_.set_dynamic_mtu_enabled(true);
    config_.set_periodic_health_check_enabled(true);
    config_.mutable_periodic_health_check_duration()->set_seconds(10);
    config_.set_periodic_health_check_port(80);
    config_.set_periodic_health_check_url("www.google.com");

    datapath_ = std::make_unique<IpSecDatapath>(config_, &looper_,
                                                &vpn_service_, &timer_manager_);
    datapath_->RegisterNotificationHandler(&notification_);
  }

  ~IpSecDatapathTest() override {
    // We need to explicitly stop the thread and join it before we destroy the
    // other class members, or else queued up runnables may reference members
    // after they are destroyed. But we don't want to destroy the thread yet,
    // because other members may still try to put stuff on it.
    looper_.Stop();
    looper_.Join();
  }

  void SetUp() override {
    HttpResponse fake_add_egress_http_response =
        ParseTextProtoOrDie(R"pb(status { code: 200 message: "OK" })pb");
    fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["192.0.2.0:8080", "[2604:ca00:f001:4::5]:2153"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "mss_detection_sock_addr": ["192.168.0.1:2153", "[2604:ca00:f004:3::5]:2153"],
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 1234,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })string");

    ASSERT_OK_AND_ASSIGN(
        fake_add_egress_response_,
        AddEgressResponse::FromProto(fake_add_egress_http_response));

    // Set the default network_info.
    network_info_.set_network_id(100);
    network_info_.set_network_type(NetworkType::CELLULAR);

    // IpSec Params
    params_ = ParseTextProtoOrDie(R"pb(
      ipsec {
        destination_address: "192.0.2.0"
        destination_address_family: V4
        destination_port: 8080
        downlink_spi: 1
        uplink_spi: 1234
        uplink_key: "uplink_key_bytes"
        downlink_key: "downlink_key_bytes"
        uplink_salt: "uplink_salt"
        downlink_salt: "downlink_salt"
        network_id: 100
        keepalive_interval_seconds: 123
      }
    )pb");

    int tunnel_sockfds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, tunnel_sockfds), 0);
    tunnel_internal_fd_ = tunnel_sockfds[0];
    tunnel_external_fd_ = tunnel_sockfds[1];
    ASSERT_OK_AND_ASSIGN(
        tunnel_, IpSecTunnel::Create(*tunnel_external_fd_, &timer_manager_));

    int network_sockfds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, network_sockfds), 0);
    network_external_fd_ = network_sockfds[1];
    params_.mutable_ipsec()->set_network_fd(network_sockfds[0]);
    ASSERT_OK_AND_ASSIGN(socket_, DatagramSocket::Create(network_sockfds[0]));

    ON_CALL(vpn_service_, GetTunnel())
        .WillByDefault([tunnel_ptr = tunnel_.get()] {
          tunnel_ptr->Reset().IgnoreError();
          return tunnel_ptr;
        });
  }

  void TearDown() override {
    if (tunnel_internal_fd_.has_value()) {
      close(*tunnel_internal_fd_);
    }
    if (tunnel_external_fd_.has_value()) {
      close(*tunnel_external_fd_);
    }
    if (network_external_fd_.has_value()) {
      close(*network_external_fd_);
    }
  }

  AddEgressResponse fake_add_egress_response_;
  std::optional<int> tunnel_internal_fd_;
  std::optional<int> tunnel_external_fd_;
  std::unique_ptr<IpSecTunnel> tunnel_;
  std::optional<int> network_external_fd_;
  std::unique_ptr<DatagramSocket> socket_;
  utils::LooperThread looper_{"IpSecDatapathTest Looper"};
  KryptonConfig config_;
  std::unique_ptr<IpSecDatapath> datapath_;
  NetworkInfo network_info_;
  MockIpSecVpnService vpn_service_;
  MockNotification notification_;
  TransformParams params_;
  Endpoint endpoint_{"192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4};
  MockTimerInterface mock_timer_interface_;
  TimerManager timer_manager_{&mock_timer_interface_};
};

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoTunnelSocket) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(nullptr));
  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, HasSubstr("null"))))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  failed.WaitForNotification();
}

TEST_F(IpSecDatapathTest, SwitchNetworkAndNoKeyMaterial) {
  EXPECT_CALL(vpn_service_, GetTunnel());

  EXPECT_THAT(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("Key Material")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkConnectsDatapathSuccessfully) {
  Endpoint endpoint("192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4);
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, endpoint, _, _))
      .WillOnce(Return(std::move(socket_)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(params_.ipsec())));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, UpdatingUplinkMtuValueCallsNotification) {
  Endpoint mss_mtu_endpoint("192.168.0.1:2153", "192.168.0.1", 2153,
                            IPProtocol::kIPv4);
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, _, mss_mtu_endpoint, _))
      .WillOnce([this](const NetworkInfo & /*network_info*/,
                       const Endpoint & /*endpoint*/,
                       const Endpoint & /*mss_mtu_detection_endpoint*/,
                       std::unique_ptr<MtuTrackerInterface> mtu_tracker) {
        mtu_tracker->UpdateUplinkMtu(1500);
        return std::move(socket_);
      });

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_CALL(notification_, DoUplinkMtuUpdate(2000, _));
  EXPECT_CALL(notification_, DoUplinkMtuUpdate(1500, _));

  network_info_.set_mtu(2000);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, DebugInfoUpdatesNumberOfDownlinkPackets) {
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  DatapathDebugInfo debug_info;
  datapath_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.downlink_packets_read(), 0);

  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.downlink_packets_read(), 1);

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchNetworkWithTransportModePortUsesPortWithIPv4) {
  // Create a new AddEgressResponse to use that has the Transport Mode Port set.
  HttpResponse fake_add_egress_http_response =
      ParseTextProtoOrDie(R"pb(status { code: 200 message: "OK" })pb");
  fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["192.0.2.0:8080"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "mss_detection_sock_addr": ["192.168.0.1:2153", "[2604:ca00:f004:3::5]:2153"],
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 1234,
        "expiry": "2020-08-07T01:06:13+00:00",
        "transport_mode_server_port": 789
      }
    })string");
  ASSERT_OK_AND_ASSIGN(
      fake_add_egress_response_,
      AddEgressResponse::FromProto(fake_add_egress_http_response));

  ASSERT_OK_AND_ASSIGN(Endpoint expected_endpoint,
                       GetEndpointFromHostPort("192.0.2.0:789"));
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, expected_endpoint, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  write(*network_external_fd_, "foo", 3);

  established.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchNetworkWithTransportModePortUsesPortWithIPv6) {
  // Create a new AddEgressResponse to use that has the Transport Mode Port set.
  HttpResponse fake_add_egress_http_response =
      ParseTextProtoOrDie(R"pb(status { code: 200 message: "OK" })pb");
  fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["[2604:ca00:f001:4::5]:2153"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "mss_detection_sock_addr": ["192.168.0.1:2153", "[2604:ca00:f004:3::5]:2153"],
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 1234,
        "expiry": "2020-08-07T01:06:13+00:00",
        "transport_mode_server_port": 789
      }
    })string");
  ASSERT_OK_AND_ASSIGN(
      fake_add_egress_response_,
      AddEgressResponse::FromProto(fake_add_egress_http_response));

  // Change some of the values to use the IPv6 addresses
  ASSERT_OK_AND_ASSIGN(Endpoint endpoint_,
                       GetEndpointFromHostPort("[2604:ca00:f001:4::5]:2153"));

  params_.mutable_ipsec()->set_destination_address("2604:ca00:f001:4::5");
  params_.mutable_ipsec()->set_destination_address_family(NetworkInfo::V6);
  params_.mutable_ipsec()->set_destination_port(2153);

  ASSERT_OK_AND_ASSIGN(Endpoint expected_endpoint,
                       GetEndpointFromHostPort("[2604:ca00:f001:4::5]:789"));
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, expected_endpoint, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  write(*network_external_fd_, "foo", 3);

  established.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SecondSwitchNetworkRekeys) {
  auto mock_socket = std::make_unique<MockIpSecSocket>();
  MockIpSecSocket *mock_socket_ptr = mock_socket.get();

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)))
      .WillOnce(Return(std::move(mock_socket)));
  EXPECT_CALL(*mock_socket_ptr, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(params_.ipsec())));
  params_.mutable_ipsec()->set_network_fd(1);
  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(params_.ipsec())))
      .Times(2);

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  absl::Notification socket_closed;
  EXPECT_CALL(*mock_socket_ptr, ReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.WaitForNotification();
    return std::vector<Packet>();
  });
  EXPECT_CALL(*mock_socket_ptr, CancelReadPackets())
      .WillOnce([&socket_closed]() {
        socket_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(notification_, DoRekey());

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  EXPECT_OK(datapath_->SetKeyMaterials(params_));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchTunnelDuringRekeyIsIgnored) {
  auto mock_socket = std::make_unique<MockIpSecSocket>();
  MockIpSecSocket *mock_socket_ptr = mock_socket.get();

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)))
      .WillOnce(Return(std::move(mock_socket)));
  EXPECT_CALL(*mock_socket_ptr, GetFd()).WillOnce(Return(1));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_CALL(*mock_socket_ptr, ReadPackets()).Times(0);
  EXPECT_CALL(*mock_socket_ptr, CancelReadPackets()).Times(0);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Switching the tunnel would normally start the packet forwarder, but this
  // should be ignored since rekey is still in progress.
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SetKeyMaterialsConfiguresIpSecWithNewKeys) {
  // Need to keep a reference to the socket to simulate data being sent.
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(params_.ipsec())));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Create new IPsec params with only updated fields
  TransformParams key_material = ParseTextProtoOrDie(R"pb(
    ipsec {
      downlink_spi: 5678
      uplink_key: "new_uplink_key"
      downlink_key: "new_downlink_key"
      uplink_salt: "new_uplink_salt"
      downlink_salt: "new_downlink_salt"
    }
  )pb");

  IpSecTransformParams ipsec_rekey_params = params_.ipsec();
  ipsec_rekey_params.set_downlink_spi(key_material.ipsec().downlink_spi());
  ipsec_rekey_params.set_uplink_key(key_material.ipsec().uplink_key());
  ipsec_rekey_params.set_downlink_key(key_material.ipsec().downlink_key());
  ipsec_rekey_params.set_uplink_salt(key_material.ipsec().uplink_salt());
  ipsec_rekey_params.set_downlink_salt(key_material.ipsec().downlink_salt());
  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(ipsec_rekey_params)));

  EXPECT_OK(datapath_->SetKeyMaterials(key_material));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchTunnelWithRunningDatapathRestartsDatapath) {
  MockTunnel new_tunnel;
  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(tunnel_.get()))
      .WillOnce(Return(&new_tunnel));
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_, ConfigureIpSec(EqualsProto(params_.ipsec())));

  absl::Notification tunnel_read_cancel;
  EXPECT_CALL(new_tunnel, ReadPackets()).WillOnce([&tunnel_read_cancel]() {
    tunnel_read_cancel.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(new_tunnel, CancelReadPackets())
      .WillOnce([&tunnel_read_cancel]() {
        tunnel_read_cancel.Notify();
        return absl::OkStatus();
      });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();
  datapath_->Stop();
  tunnel_read_cancel.WaitForNotification();
}

TEST_F(IpSecDatapathTest,
       SwitchTunnelWithFailureBeforePrepareDoesNotStartDatapath) {
  EXPECT_CALL(vpn_service_, GetTunnel());
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });
  EXPECT_CALL(notification_, DatapathFailed);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest,
       SwitchTunnelWithFailureAfterPrepareDoesNotStartDatapath) {
  EXPECT_CALL(vpn_service_, GetTunnel());
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });
  EXPECT_CALL(notification_, DatapathFailed);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->PrepareForTunnelSwitch();
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);
  datapath_->SwitchTunnel();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest,
       SwitchTunnelWithTwoFailuresAfterPrepareOnlyHandlesOne) {
  EXPECT_CALL(vpn_service_, GetTunnel());
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });
  EXPECT_CALL(notification_, DatapathFailed);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, so that we know everything is running.
  write(*network_external_fd_, "foo", 3);
  established.WaitForNotification();

  datapath_->PrepareForTunnelSwitch();
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);
  datapath_->SwitchTunnel();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, FailureAfterSwitchTunnelIsIgnored) {
  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 0);

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchNetworkBadNetworkSocket) {
  // create failure to create network socket.
  EXPECT_CALL(notification_, DatapathFailed);
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(absl::InternalError("Failure")));

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, HealthCheckNotifications) {
  // Verifies that Session notifications are sent from the datapath in response
  // to health check events.
  EXPECT_CALL(notification_, DatapathHealthCheckStarting).Times(2);
  EXPECT_CALL(notification_, DatapathHealthCheckSucceeded);
  EXPECT_CALL(notification_, DatapathFailed(absl::InternalError("Failure")));
  datapath_->HealthCheckStarting();
  datapath_->HealthCheckSucceeded();
  datapath_->HealthCheckStarting();
  datapath_->HealthCheckFailed(absl::InternalError("Failure"));
}

TEST_F(IpSecDatapathTest, HealthCheckFailureHandled) {
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  int health_check_timer_id = 0;
  absl::Notification timer_started;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(10))))
      .WillOnce([&health_check_timer_id, &timer_started](
                    int id, absl::Duration /*duration*/) {
        health_check_timer_id = id;
        timer_started.Notify();
        return absl::OkStatus();
      });

  // DatapathFailed should be called when the health check fails.
  absl::Notification failed;
  EXPECT_CALL(notification_, DatapathFailed).WillOnce([&failed]() {
    failed.Notify();
  });
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  // Health check should be started once this has been called.
  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  // Verify datapath receives health check notifications when expected.
  EXPECT_CALL(notification_, DatapathHealthCheckStarting);
  EXPECT_CALL(notification_, DatapathHealthCheckSucceeded).Times(0);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic so that the health check is started.
  write(*network_external_fd_, "foo", 3);

  // Wait for DatapathEstablished notification.
  established.WaitForNotification();

  // Wait for the timer for the health check to be started.
  timer_started.WaitForNotification();

  // Simulate the health check timer expiring.
  mock_timer_interface_.TimerExpiry(health_check_timer_id);

  // Wait for the DatapathFailed notification from the failed health check.
  failed.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, NetworkWriteFailure) {
  auto mock_socket = std::make_unique<MockIpSecSocket>();
  MockIpSecSocket *mock_socket_ptr = mock_socket.get();

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(mock_socket)));
  EXPECT_CALL(*mock_socket_ptr, GetFd()).WillOnce(Return(1));

  absl::Notification failed;
  EXPECT_CALL(notification_, DatapathFailed).WillOnce([&failed]() {
    failed.Notify();
  });

  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  absl::Notification socket_closed;
  // Simulate a blocking read until the socket is closed.
  EXPECT_CALL(*mock_socket_ptr, ReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Simulate a failed write.
  EXPECT_CALL(*mock_socket_ptr, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(*mock_socket_ptr, CancelReadPackets())
      .WillOnce([&socket_closed]() {
        socket_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  write(*tunnel_internal_fd_, "foo", 3);

  // Wait for the failure to occur.
  failed.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, TunnelWriteFailure) {
  MockTunnel mock_tunnel;
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&mock_tunnel));

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);

  absl::Notification failed;
  EXPECT_CALL(notification_, DatapathPermanentFailure).WillOnce([&failed]() {
    failed.Notify();
  });

  absl::Notification tunnel_closed;
  // Simulate a blocking read until the socket is closed.
  EXPECT_CALL(mock_tunnel, ReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Simulate a failed write.
  EXPECT_CALL(mock_tunnel, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(mock_tunnel, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  // Simulate some network traffic, which will be written to the tunnel.
  write(*network_external_fd_, "foo", 3);

  // Wait for the failure to occur.
  failed.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, NotificationFromOldPacketForwarderIsIgnored) {
  auto mock_socket = std::make_unique<MockIpSecSocket>();
  MockIpSecSocket *mock_socket_ptr = mock_socket.get();

  EXPECT_CALL(*mock_socket_ptr, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)))
      .WillOnce(Return(std::move(mock_socket)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  absl::Notification socket_closed;

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(*mock_socket_ptr, ReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Unblock the ReadPackets call.
  EXPECT_CALL(*mock_socket_ptr, CancelReadPackets())
      .WillOnce([&socket_closed]() {
        socket_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 2));
  EXPECT_OK(datapath_->SetKeyMaterials(params_));
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, NotificationReceivedWhileDatapathInactiveIsIgnored) {
  MockTunnel mock_tunnel;
  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(tunnel_.get()))
      .WillOnce(Return(&mock_tunnel));

  auto mock_socket = std::make_unique<MockIpSecSocket>();
  MockIpSecSocket *mock_socket_ptr = mock_socket.get();

  EXPECT_CALL(*mock_socket_ptr, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)))
      .WillOnce(Return(std::move(mock_socket)));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 2));
  datapath_->IpSecPacketForwarderFailed(absl::InternalError("Failure"), 1);

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchTunnelWithGetTunnelErrorCausesFailure) {
  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(tunnel_.get()))
      .WillOnce(Return(absl::InternalError("Failure")));
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, StrEq("Failure"))))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();

  failed.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchTunnelWithGetTunnelNullCausesFailure) {
  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(tunnel_.get()))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_)));

  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, HasSubstr("null"))))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  datapath_->PrepareForTunnelSwitch();
  datapath_->SwitchTunnel();

  failed.WaitForNotification();

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, UplinkMtuUpdateHandler) {
  absl::Notification mtu_update_done;
  EXPECT_CALL(notification_, DoUplinkMtuUpdate(1, 2))
      .WillOnce([&mtu_update_done]() { mtu_update_done.Notify(); });

  datapath_->UplinkMtuUpdated(1, 2);

  mtu_update_done.WaitForNotification();
}

TEST_F(IpSecDatapathTest, DownlinkMtuUpdateHandler) {
  absl::Notification mtu_update_done;
  EXPECT_CALL(notification_, DoDownlinkMtuUpdate(576))
      .WillOnce([&mtu_update_done]() { mtu_update_done.Notify(); });

  datapath_->DownlinkMtuUpdated(576);

  mtu_update_done.WaitForNotification();
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
