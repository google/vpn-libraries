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
#include <optional>
#include <utility>
#include <vector>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
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
#include "util/task/status.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::_;
using ::testing::Eq;
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
        "mss_detection_sock_addr": ["192.168.0.1:2153", "[2604:ca00:f004:3::5]:2153"],
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
    params->set_uplink_salt("uplink_salt");
    params->set_downlink_salt("downlink_salt");
    params->set_network_id(100);
    params->set_network_fd(1);
    params->set_keepalive_interval_seconds(123);
  }

  AddEgressResponse fake_add_egress_response_;
  utils::LooperThread looper_{"Krypton Looper"};
  KryptonConfig config_;
  std::unique_ptr<IpSecDatapath> datapath_;
  NetworkInfo network_info_;
  MockIpSecVpnService vpn_service_;
  MockNotification notification_;
  MockTunnel tunnel_;
  TransformParams params_;
  Endpoint endpoint_{"192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4};
  MockTimerInterface mock_timer_interface_;
  TimerManager timer_manager_{&mock_timer_interface_};
};

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoNetworkSocket) {
  EXPECT_THAT(datapath_->SwitchNetwork(1234, endpoint_, std::nullopt, 1),
              StatusIs(util::error::INVALID_ARGUMENT,
                       testing::HasSubstr("network_info")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoTunnelSocket) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(nullptr));
  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, HasSubstr("null"))))
      .WillOnce([&failed]() { failed.Notify(); });
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(IpSecDatapathTest, SwitchNetworkAndNoKeyMaterial) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  //  Set KeyMaterial but not of type Ipsec.
  EXPECT_THAT(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1),
              StatusIs(util::error::FAILED_PRECONDITION,
                       testing::HasSubstr("Key Material")));
}

TEST_F(IpSecDatapathTest, SwitchNetworkHappyPath) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  Endpoint expected_endpoint("192.0.2.0:8080", "192.0.2.0", 8080,
                             IPProtocol::kIPv4);
  Endpoint expected_mss_mtu_endpoint("192.168.0.1:2153", "192.168.0.1", 2153,
                                     IPProtocol::kIPv4);

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, expected_endpoint,
                                           expected_mss_mtu_endpoint, _))
      .WillOnce(
          [&socket_ptr](const NetworkInfo & /*network_info*/,
                        const Endpoint & /*endpoint*/,
                        const Endpoint & /*mss_mtu_detection_endpoint*/,
                        std::unique_ptr<MtuTrackerInterface> mtu_tracker) {
            mtu_tracker->UpdateUplinkMtu(1500);
            return std::move(socket_ptr);
          });
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
      .WillOnce(Return(std::move(packets)))
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

  EXPECT_CALL(notification_, DoUplinkMtuUpdate(2000, _)).Times(1);
  EXPECT_CALL(notification_, DoUplinkMtuUpdate(1500, _)).Times(1);

  network_info_.set_mtu(2000);

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  EXPECT_TRUE(
      established.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  DatapathDebugInfo debug_info;
  datapath_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.downlink_packets_read(), 1);

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SetKeyMaterials) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  Endpoint expected_endpoint("192.0.2.0:8080", "192.0.2.0", 8080,
                             IPProtocol::kIPv4);
  Endpoint expected_mss_mtu_endpoint("192.168.0.1:2153", "192.168.0.1", 2153,
                                     IPProtocol::kIPv4);

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, expected_endpoint,
                                           expected_mss_mtu_endpoint, _))
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_,
              ConfigureIpSec(testing::EqualsProto(params_.ipsec())));

  absl::Notification established;
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  std::vector<Packet> packets1;
  std::vector<Packet> packets2;
  packets1.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});
  packets2.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});

  absl::Notification socket_closed1;
  absl::Notification socket_closed2;
  absl::Notification last_read_done;

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce(Return(std::move(packets1)))
      .WillOnce([&socket_closed1]() {
        socket_closed1.WaitForNotification();
        return std::vector<Packet>();
      })
      .WillOnce([&last_read_done, &packets2] {
        last_read_done.Notify();
        return std::move(packets2);
      })
      .WillOnce([&socket_closed2]() {
        socket_closed2.WaitForNotification();
        return std::vector<Packet>();
      });

  // Closed by both the packet forwarder and the datapath.
  EXPECT_CALL(*socket, CancelReadPackets())
      .WillOnce([&socket_closed1]() {
        socket_closed1.Notify();
        return absl::OkStatus();
      })
      .WillOnce([&socket_closed2]() {
        socket_closed2.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(*socket, Close()).WillOnce(Return(absl::OkStatus()));

  absl::Notification tunnel_closed1;
  absl::Notification tunnel_closed2;

  EXPECT_CALL(tunnel_, ReadPackets())
      .WillOnce([&tunnel_closed1]() {
        tunnel_closed1.WaitForNotification();
        return std::vector<Packet>();
      })
      .WillOnce([&tunnel_closed2]() {
        tunnel_closed2.WaitForNotification();
        return std::vector<Packet>();
      });

  EXPECT_CALL(tunnel_, CancelReadPackets())
      .WillOnce([&tunnel_closed1]() {
        tunnel_closed1.Notify();
        return absl::OkStatus();
      })
      .WillOnce([&tunnel_closed2]() {
        tunnel_closed2.Notify();
        return absl::OkStatus();
      });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillRepeatedly(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  EXPECT_TRUE(
      established.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  // Create new IPsec params with only updated fields
  TransformParams rekey_params;
  rekey_params.mutable_ipsec()->set_downlink_spi(5678);
  rekey_params.mutable_ipsec()->set_uplink_key("new_uplink_key");
  rekey_params.mutable_ipsec()->set_downlink_key("new_downlink_key");
  rekey_params.mutable_ipsec()->set_uplink_salt("new_uplink_salt");
  rekey_params.mutable_ipsec()->set_downlink_salt("new_downlink_salt");

  // All fields not specific to the rekey should carry over
  params_.mutable_ipsec()->set_downlink_spi(
      rekey_params.ipsec().downlink_spi());
  params_.mutable_ipsec()->set_uplink_key(rekey_params.ipsec().uplink_key());
  params_.mutable_ipsec()->set_downlink_key(
      rekey_params.ipsec().downlink_key());
  params_.mutable_ipsec()->set_uplink_salt(rekey_params.ipsec().uplink_salt());
  params_.mutable_ipsec()->set_downlink_salt(
      rekey_params.ipsec().downlink_salt());
  EXPECT_CALL(vpn_service_,
              ConfigureIpSec(testing::EqualsProto(params_.ipsec())));

  EXPECT_OK(datapath_->SetKeyMaterials(rekey_params));

  EXPECT_TRUE(
      last_read_done.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, SwitchTunnel) {
  MockTunnel new_tunnel;
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  EXPECT_CALL(vpn_service_,
              ConfigureIpSec(testing::EqualsProto(params_.ipsec())));

  absl::Notification socket_read_cancel_1;
  absl::Notification socket_read_cancel_2;
  absl::Notification tunnel_read_cancel_1;
  absl::Notification tunnel_read_cancel_2;

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce([&socket_read_cancel_1]() {
        socket_read_cancel_1.WaitForNotification();
        return std::vector<Packet>();
      })
      .WillOnce([&socket_read_cancel_2]() {
        socket_read_cancel_2.WaitForNotification();
        return std::vector<Packet>();
      });

  // Closed by both the packet forwarder and the datapath.
  EXPECT_CALL(*socket, CancelReadPackets())
      .WillOnce([&socket_read_cancel_1]() {
        socket_read_cancel_1.Notify();
        return absl::OkStatus();
      })
      .WillOnce([&socket_read_cancel_2]() {
        socket_read_cancel_2.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(*socket, Close()).WillOnce(Return(absl::OkStatus()));

  EXPECT_CALL(tunnel_, ReadPackets()).WillOnce([&tunnel_read_cancel_1]() {
    tunnel_read_cancel_1.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(new_tunnel, ReadPackets()).WillOnce([&tunnel_read_cancel_2]() {
    tunnel_read_cancel_2.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_read_cancel_1]() {
    tunnel_read_cancel_1.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(new_tunnel, CancelReadPackets())
      .WillOnce([&tunnel_read_cancel_2]() {
        tunnel_read_cancel_2.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(&tunnel_))
      .WillOnce(Return(&new_tunnel));

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));
  datapath_->PrepareForTunnelSwitch();
  EXPECT_TRUE(tunnel_read_cancel_1.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
  datapath_->SwitchTunnel();
  datapath_->Stop();
  EXPECT_TRUE(tunnel_read_cancel_2.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(IpSecDatapathTest, SwitchNetworkBadNetworkSocket) {
  // create failure to create network socket.
  EXPECT_CALL(notification_, DatapathFailed).Times(1);
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(absl::InternalError("Failure")));

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, HealthCheckFailureHandled) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  Endpoint expected_endpoint("192.0.2.0:8080", "192.0.2.0", 8080,
                             IPProtocol::kIPv4);
  Endpoint expected_mss_mtu_endpoint("192.168.0.1:2153", "192.168.0.1", 2153,
                                     IPProtocol::kIPv4);

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_,
              CreateProtectedNetworkSocket(_, expected_endpoint,
                                           expected_mss_mtu_endpoint, _))
      .WillOnce(
          [&socket_ptr](const NetworkInfo & /*network_info*/,
                        const Endpoint & /*endpoint*/,
                        const Endpoint & /*mss_mtu_detection_endpoint*/,
                        std::unique_ptr<MtuTrackerInterface> mtu_tracker) {
            mtu_tracker->UpdateUplinkMtu(1500);
            return std::move(socket_ptr);
          });
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

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

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});

  absl::Notification established;
  absl::Notification socket_closed;
  absl::Notification tunnel_closed;

  // Health check should be started once this has been called.
  EXPECT_CALL(notification_, DatapathEstablished).WillOnce([&established]() {
    established.Notify();
  });

  // Simulate some network traffic so that the health check is started and then
  // simulate a blocking read.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce(Return(std::move(packets)))
      .WillOnce([&socket_closed]() {
        socket_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Unblock the ReadPackets call.
  EXPECT_CALL(*socket, CancelReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(*socket, Close()).WillOnce(Return(absl::OkStatus()));

  // Simulate a blocking read.
  EXPECT_CALL(tunnel_, ReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Unblock the ReadPackets call.
  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Wait for DatapathEstablished notification.
  EXPECT_TRUE(
      established.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  // Wait for the timer for the health check to be started.
  EXPECT_TRUE(
      timer_started.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  // Simulate the health check timer expiring.
  mock_timer_interface_.TimerExpiry(health_check_timer_id);

  // Wait for the DatapathFailed notification from the failed health check.
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, NetworkWriteFailure) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});

  absl::Notification failed;
  absl::Notification socket_closed;
  absl::Notification tunnel_closed;

  EXPECT_CALL(notification_, DatapathFailed).WillOnce([&failed]() {
    failed.Notify();
  });

  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  // Simulate a blocking read until the socket is closed.
  EXPECT_CALL(*socket, ReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Simulate a failed write.
  EXPECT_CALL(*socket, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(*socket, CancelReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.Notify();
    return absl::OkStatus();
  });

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(tunnel_, ReadPackets())
      .WillOnce(Return(std::move(packets)))
      .WillOnce([&tunnel_closed]() {
        tunnel_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Unblock the ReadPackets call.
  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Wait for the failure to occur.
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, TunnelWriteFailure) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});

  absl::Notification failed;
  absl::Notification socket_closed;
  absl::Notification tunnel_closed;

  EXPECT_CALL(notification_, DatapathFailed).Times(0);

  EXPECT_CALL(notification_, DatapathPermanentFailure).WillOnce([&failed]() {
    failed.Notify();
  });

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce(Return(std::move(packets)))
      .WillOnce([&socket_closed]() {
        socket_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Unblock the ReadPackets call.
  EXPECT_CALL(*socket, CancelReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.Notify();
    return absl::OkStatus();
  });

  // Simulate a blocking read until the socket is closed.
  EXPECT_CALL(tunnel_, ReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Simulate a failed write.
  EXPECT_CALL(tunnel_, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  // Wait for the failure to occur.
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  datapath_->Stop();
}

TEST_F(IpSecDatapathTest, IgnoreOldForwarderNotifications) {
  auto socket_ptr = std::make_unique<MockIpSecSocket>();

  // Need to keep a reference to the socket to simulate data being sent.
  MockIpSecSocket *socket = socket_ptr.get();
  EXPECT_CALL(vpn_service_, CreateProtectedNetworkSocket(_, _, _, _))
      .WillOnce(Return(std::move(socket_ptr)));
  EXPECT_CALL(*socket, GetFd()).WillOnce(Return(1));

  std::vector<Packet> packets1;
  std::vector<Packet> packets2;
  packets1.emplace_back("foo", 3, IPProtocol::kIPv6, [] {});
  packets2.emplace_back("bar", 3, IPProtocol::kIPv6, [] {});

  int failure_count = 0;

  absl::Notification socket_closed;
  absl::Notification tunnel_closed;

  EXPECT_CALL(notification_, DatapathFailed).WillRepeatedly([&failure_count]() {
    ++failure_count;
  });

  EXPECT_CALL(notification_, DatapathPermanentFailure)
      .WillRepeatedly([&failure_count]() { ++failure_count; });

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(*socket, ReadPackets())
      .WillOnce(Return(std::move(packets1)))
      .WillOnce([&socket_closed]() {
        socket_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Simulate a failed write.
  EXPECT_CALL(*socket, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(*socket, CancelReadPackets()).WillOnce([&socket_closed]() {
    socket_closed.Notify();
    return absl::OkStatus();
  });

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(tunnel_, ReadPackets())
      .WillOnce(Return(std::move(packets2)))
      .WillOnce([&tunnel_closed]() {
        tunnel_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Simulate a failed write.
  EXPECT_CALL(tunnel_, WritePackets(_))
      .WillOnce(Return(absl::InternalError("Failure")));

  // Unblock the ReadPackets call.
  EXPECT_CALL(tunnel_, CancelReadPackets()).WillOnce([&tunnel_closed]() {
    tunnel_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_OK(datapath_->Start(fake_add_egress_response_, params_));
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_->SwitchNetwork(1234, endpoint_, network_info_, 1));

  datapath_->Stop();

  // Delete the datapath to make sure its internal looper has finished.
  datapath_ = nullptr;

  // Verify at most one of the failure notifications was processed. If stop was
  // processed first then both failure notifications may have been ignored.
  EXPECT_LE(failure_count, 1);
}

TEST_F(IpSecDatapathTest, SwitchTunnelError) {
  EXPECT_CALL(vpn_service_, GetTunnel())
      .WillOnce(Return(absl::InternalError("Failure")));
  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, StrEq("Failure"))))
      .WillOnce([&failed]() { failed.Notify(); });
  datapath_->SwitchTunnel();
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(IpSecDatapathTest, SwitchTunnelNullTunnel) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(nullptr));
  absl::Notification failed;
  EXPECT_CALL(notification_,
              DatapathPermanentFailure(
                  StatusIs(absl::StatusCode::kInternal, HasSubstr("null"))))
      .WillOnce([&failed]() { failed.Notify(); });
  datapath_->SwitchTunnel();
  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(IpSecDatapathTest, UplinkMtuUpdateHandler) {
  absl::Notification mtu_update_done;
  EXPECT_CALL(notification_, DoUplinkMtuUpdate(1, 2))
      .WillOnce([&mtu_update_done]() { mtu_update_done.Notify(); });
  datapath_->UplinkMtuUpdated(1, 2);
  EXPECT_TRUE(mtu_update_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(IpSecDatapathTest, DownlinkMtuUpdateHandler) {
  absl::Notification mtu_update_done;
  EXPECT_CALL(notification_, DoDownlinkMtuUpdate(576))
      .WillOnce([&mtu_update_done]() { mtu_update_done.Notify(); });
  datapath_->DownlinkMtuUpdated(576);
  EXPECT_TRUE(mtu_update_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
