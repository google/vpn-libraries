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

#include "privacy/net/krypton/tunnel_manager.h"

#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace {

constexpr auto tunnel_data_string = R"pb(is_metered: false)pb";

using ::testing::_;
using ::testing::Return;

class TunnelManagerTest : public ::testing::Test {
 public:
  void SetUp() override {}

  void TearDown() override {}

  TunFdData buildTunFdData() {
    TunFdData tunnel_data_;
    tunnel_data_.set_is_metered(false);
    return tunnel_data_;
  }

 protected:
  MockVpnService vpn_service_;
};

TEST_F(TunnelManagerTest, StartWithSafeDisconnectDisabledNoTunnel) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).Times(0);

  ASSERT_OK(tunnel_manager.Start());
}

TEST_F(TunnelManagerTest, StartWithSafeDisconnectEnabledNoTunnel) {
  auto tunnel_manager = TunnelManager(&vpn_service_, true);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).Times(0);

  ASSERT_OK(tunnel_manager.Start());
}

TEST_F(TunnelManagerTest,
       StartSessionWithSafeDisconnectDisabledThenCreateTunnel) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelOutlivesSessionWhenSafeDisconnectEnabled) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelAndSessionDieWhenSafeDisconnectDisabled) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));

  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelUnchangedWhenTogglingSafeDisconnect) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(false);
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, GetTunnelReturnsOldTunnelAfterSafeDisconnect) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(1)
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest,
       CreateNewTunnelAfterStartingWithSafeDisconnectEnabled) {
  auto tunnel_manager = TunnelManager(&vpn_service_, true);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, SessionStartAndStopWithSafeDisconnectOff) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, StopClosesActiveTunnel) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.Stop();
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest,
       DisablingSafeDisconnectClosesTunnelWhenNoActiveSession) {
  auto tunnel_manager = TunnelManager(&vpn_service_, true);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(false);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelAndSessionDieWhenSafeDisconnectOverridden) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/true);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest,
       TerminateSessionCalledBeforeStartSessionResultsInInactiveTunnel) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  ASSERT_OK(tunnel_manager.Start());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/true);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, RecreateTunnelReturnsOldTunnel) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/true);
  // Snooze will bypass safe disconnect, meaning that the active_tunnel_ is
  // closed. This simulates snooze.
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/true);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfOneAlreadyPresent) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/true);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfSafeDisconnectNotEnabled) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(Return(absl::OkStatus()));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.EnsureTunnelIsUp(buildTunFdData()));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/false);
  tunnel_manager.DatapathStopped(/*forceFailOpen=*/false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfNoActiveTunnelDataAvailable) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.DatapathStarted();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
