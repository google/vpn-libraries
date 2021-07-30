// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"

#include <memory>

#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/test_packet_pipe.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

using testing::_;

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {
namespace {

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
  }

  void SetUp() override {
    fake_add_egress_response_ = std::make_shared<AddEgressResponse>();
  }

  void TearDown() override { fake_add_egress_response_.reset(); }

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

  std::shared_ptr<AddEgressResponse> fake_add_egress_response_;
  utils::LooperThread looper_{"Krypton Looper"};
  IpSecDatapath datapath_{&looper_, &vpn_service_};
  NetworkInfo network_info_;
  TestPacketPipe tunnel_{1};
  MockVpnService vpn_service_;
  MockNotification notification_;
  TransformParams params_;
  Endpoint endpoint_{"192.0.2.0:8080", "192.0.2.0", 8080, IPProtocol::kIPv4};
};

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoTunnelSocket) {
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, nullptr, 1),
              absl::InvalidArgumentError("tunnel is null"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoIpSecParams) {
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams is null"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoUplinkKey) {
  auto params = params_.mutable_ipsec();
  params->set_downlink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no uplink_key"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoDownlinkKey) {
  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no downlink_key"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoUplinkSalt) {
  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no uplink_salt"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkFailureNoDownlinkSalt) {
  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_key(std::string(32, 'z'));
  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_THAT(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1),
              absl::InvalidArgumentError(
                  "TransformParams.IpSecTransformParams has no downlink_salt"));
}

TEST_F(IpSecDatapathTest, SwitchNetworkHappyPath) {
  auto pipe_ptr = std::make_unique<TestPacketPipe>(2);
  auto pipe = pipe_ptr.get();
  EXPECT_CALL(vpn_service_, CreateNetworkPipe(_, _))
      .WillOnce(::testing::Return(testing::ByMove(std::move(pipe_ptr))));

  EXPECT_CALL(notification_, DatapathFailed).Times(0);
  EXPECT_CALL(notification_, DatapathPermanentFailure).Times(0);

  auto params = params_.mutable_ipsec();
  params->set_uplink_key(std::string(32, 'z'));
  params->set_downlink_key(std::string(32, 'z'));
  params->set_uplink_salt(std::string(4, 'a'));
  params->set_downlink_salt(std::string(4, 'a'));

  EXPECT_OK(datapath_.Start(fake_add_egress_response_, params_));
  EXPECT_OK(datapath_.SwitchNetwork(1, endpoint_, network_info_, &tunnel_, 1));

  // Simulate some network traffic, so that we know everything is running.
  EXPECT_CALL(notification_, DatapathEstablished);
  Encryptor encryptor(2);
  EXPECT_OK(encryptor.Start(params_));
  Packet unencrypted("foo", 3, IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor.Process(unencrypted));
  ASSERT_OK_AND_ASSIGN(auto handler, pipe->GetReadHandler());
  EXPECT_TRUE(handler(absl::OkStatus(), std::move(encrypted)));
  WaitForNotifications();

  pipe = nullptr;
  datapath_.Stop();
}

}  // namespace
}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
