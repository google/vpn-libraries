// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/test_packet_pipe.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "util/task/status_macros.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;

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

class MockIpSecVpnService : public IpSecDatapath::IpSecVpnServiceInterface {
 public:
  MOCK_METHOD(DatapathInterface *, BuildDatapath,
              (const KryptonConfig &, utils::LooperThread *,
               TimerManager *timer_manager),
              (override));

  MOCK_METHOD(absl::Status, CreateTunnel, (const TunFdData &), (override));

  MOCK_METHOD(PacketPipe *, GetTunnel, (), (override));

  MOCK_METHOD(void, CloseTunnel, (), (override));

  MOCK_METHOD(absl::StatusOr<std::unique_ptr<PacketPipe>>, CreateNetworkPipe,
              (const NetworkInfo &, const Endpoint &), (override));

  MOCK_METHOD(absl::Status, CheckConnection, (), (override));
};

KryptonConfig CreateTestConfig() {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(300);
  return config;
}

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
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};
  MockIpSecVpnService vpn_service_;
  IpSecDatapath datapath_{CreateTestConfig(), &looper_, &vpn_service_,
                          &timer_manager_};
  NetworkInfo network_info_;
  TestPacketPipe tunnel_{1};
  MockNotification notification_;
  TransformParams params_;
  Endpoint endpoint_{"192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4};
};

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoTunnelSocket) {
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError("tunnel is null"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoIpSecParams) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams is null"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoUplinkKey) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  auto params = params_.mutable_ipsec();
  params->set_downlink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no uplink_key"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoDownlinkKey) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no downlink_key"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoUplinkSalt) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no uplink_salt"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoDownlinkSalt) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no downlink_salt"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkHappyPath) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(10)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(300)))
      .WillOnce(Return(absl::OkStatus()));

  auto pipe_ptr = std::make_unique<TestPacketPipe>(2);
  auto pipe = pipe_ptr.get();
  EXPECT_CALL(vpn_service_, CreateNetworkPipe(_, _))
      .WillOnce(Return(testing::ByMove(std::move(pipe_ptr))));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_downlink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_salt(std::string(4, 'a'));

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1));

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(notification_, DatapathEstablished);
  ASSERT_OK_AND_ASSIGN(auto encryptor, Encryptor::Create(2, params_));
  Packet unencrypted("foo", 3, IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor->Process(unencrypted));
  std::vector<Packet> packets;
  packets.emplace_back(std::move(encrypted));
  ASSERT_OK_AND_ASSIGN(auto handler, pipe->GetReadHandler());
  EXPECT_TRUE(handler(absl::OkStatus(), std::move(packets)));
  WaitForNotifications();

  pipe = nullptr;
  datapath_.Stop();
}

TEST_F(IpSecDatapathTest, SwitchNetworkTimeout) {
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));
  int connecting_timeout_timer_id;
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(10)))
      .Times(2)
      .WillRepeatedly(DoAll(SaveArg<0>(&connecting_timeout_timer_id),
                            Return(absl::OkStatus())));

  TestPacketPipe *pipe;
  EXPECT_CALL(vpn_service_, CreateNetworkPipe(_, _))
      .Times(2)
      .WillRepeatedly([&] {
        auto pipe_ptr = std::make_unique<TestPacketPipe>(2);
        pipe = pipe_ptr.get();
        return pipe_ptr;
      });

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_downlink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_salt(std::string(4, 'a'));

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1));

  // Expire the first connecting timer. The connection will be retried once, and
  // the timer ID above will be overwritten with a new one.
  EXPECT_CALL(timer_interface_, CancelTimer(connecting_timeout_timer_id))
      .Times(0);
  int old_timer_id = connecting_timeout_timer_id;
  timer_interface_.TimerExpiry(connecting_timeout_timer_id);
  EXPECT_NE(old_timer_id, connecting_timeout_timer_id);

  // Expire the second connecting timer. The datapath should signal connetion
  // failure.
  absl::Notification notify_failed;
  EXPECT_CALL(notification_, DatapathFailed).WillOnce([&] {
    notify_failed.Notify();
  });
  EXPECT_CALL(timer_interface_, CancelTimer(connecting_timeout_timer_id))
      .Times(0);
  timer_interface_.TimerExpiry(connecting_timeout_timer_id);
  notify_failed.WaitForNotification();

  pipe = nullptr;
  datapath_.Stop();
}

TEST_F(IpSecDatapathTest, HealthCheckFailed) {
  absl::Notification notify_enter;
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(300)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(vpn_service_, CheckConnection()).WillOnce([&] {
    notify_enter.Notify();
    return absl::InternalError("Foo");
  });

  // Trigger when PacketForwarderConnected() is called.
  EXPECT_CALL(notification_, DatapathEstablished);

  // Health check callback.
  EXPECT_CALL(timer_interface_, CancelTimer(0));

  absl::Notification notify_failed;
  EXPECT_CALL(notification_, DatapathFailed).WillOnce([&] {
    notify_failed.Notify();
  });

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));

  // Start the health check timer.
  datapath_.PacketForwarderConnected();

  // Wait for DatapathEstablished notification before moving forward.
  WaitForNotifications();

  // Trigger health check resule.
  timer_interface_.TimerExpiry(0);

  notify_enter.WaitForNotification();

  // Wait for DatapathFailed.
  notify_failed.WaitForNotification();

  datapath_.Stop();
}

TEST_F(IpSecDatapathTest, SwitchNetworkWhenHealthCheckIsInProgress) {
  absl::Notification notify_enter, notify_exit;
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(10)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(300)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(vpn_service_, CheckConnection()).WillOnce([&] {
    notify_enter.Notify();
    notify_exit.WaitForNotification();
    return absl::InternalError("Foo");
  });

  auto pipe_ptr = std::make_unique<TestPacketPipe>(2);
  auto pipe = pipe_ptr.get();
  EXPECT_CALL(vpn_service_, CreateNetworkPipe(_, _))
      .WillOnce(Return(testing::ByMove(std::move(pipe_ptr))));
  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_downlink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_salt(std::string(4, 'a'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  datapath_.PacketForwarderConnected();

  // Trigger health check.
  timer_interface_.TimerExpiry(0);
  timer_interface_.TimerExpiry(1);

  // Verify the previous health check result is discarded since it's cancelled.
  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(vpn_service_, GetTunnel()).WillOnce(Return(&tunnel_));

  notify_enter.WaitForNotification();
  EXPECT_OK(datapath_.SwitchNetwork(1, endpoint_, network_info_, 1));
  notify_exit.Notify();

  pipe = nullptr;
  datapath_.Stop();
}

}  // namespace
}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
