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

#include "privacy/net/krypton/tunnel_manager.h"

#include <memory>

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/test_packet_pipe.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

constexpr auto tunnel_data_string = R"pb(is_metered: false)pb";

using ::testing::_;
using ::testing::status::IsOk;
using ::testing::status::IsOkAndHolds;

// Helper macro for returning a PacketPipe wrapping a file descriptor, since
// it's complicated and used in many locations.
#define RETURN_TEST_PIPE(id) \
  ::testing::Return(testing::ByMove(std::make_unique<TestPacketPipe>(id)))

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
  int tun_fd = 0x1000;
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest, TunnelOutlivesSessionWhenSafeDisconnectEnabled) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelAndSessionDieWhenSafeDisconnectDisabled) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, TunnelUnchangedWhenTogglingSafeDisconnect) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(false);
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest, GetTunnelReturnsOldTunnelAfterSafeDisconnect) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(1)
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest,
       CreateNewTunnelAfterStartingWithSafeDisconnectEnabled) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, true);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(), nullptr);

  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest, SessionStartAndStopWithSafeDisconnectOff) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);

  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
  EXPECT_TRUE(tunnel_manager.IsTunnelActive());

  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, StopClosesActiveTunnel) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);
  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);

  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.Stop();
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
}

TEST_F(TunnelManagerTest,
       DisablingSafeDisconnectClosesTunnelWhenNoActiveSession) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, true);
  EXPECT_CALL(vpn_service_, CreateTunnel(_)).WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(), nullptr);

  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(false);
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
}

TEST_F(TunnelManagerTest, TunnelAndSessionDieWhenSafeDisconnectOverridden) {
  int tun_fd = 0x1000;
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/true);
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest,
       TerminateSessionCalledBeforeStartSessionResultsInInactiveTunnel) {
  auto tunnel_manager = TunnelManager(&vpn_service_, false);

  ASSERT_OK(tunnel_manager.Start());

  tunnel_manager.SetSafeDisconnectEnabled(true);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/true);
  EXPECT_EQ(tunnel_manager.active_tunnel_test_only(), nullptr);
  EXPECT_FALSE(tunnel_manager.IsTunnelActive());
}

TEST_F(TunnelManagerTest, RecreateTunnelReturnsOldTunnel) {
  int tun_fd = 0x1000;
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/true);
  // Snooze will bypass safe disconnect, meaning that the active_tunnel_ is
  // closed. This simulates snooze.
  tunnel_manager.TerminateSession(/*forceFailOpen=*/true);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));
  tunnel_manager.StartSession();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  ASSERT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfOneAlreadyPresent) {
  int tun_fd = 0x1000;
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/true);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.StartSession();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  ASSERT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfSafeDisconnectNotEnabled) {
  int tun_fd = 0x1000;
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .WillOnce(RETURN_TEST_PIPE(tun_fd));

  ASSERT_OK(tunnel_manager.Start());
  tunnel_manager.StartSession();
  ASSERT_THAT(tunnel_manager.GetTunnel(buildTunFdData()),
              IsOkAndHolds(PacketPipeHasFd(tun_fd)));
  EXPECT_THAT(tunnel_manager.active_tunnel_test_only(),
              PacketPipeHasFd(tun_fd));

  tunnel_manager.SetSafeDisconnectEnabled(/*enable=*/false);
  tunnel_manager.TerminateSession(/*forceFailOpen=*/false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.StartSession();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  ASSERT_THAT(tunnel_manager.active_tunnel_test_only(), nullptr);
}

TEST_F(TunnelManagerTest, DoNotRecreateTunnelIfNoActiveTunnelDataAvailable) {
  TunnelManager tunnel_manager = TunnelManager(&vpn_service_, false);

  EXPECT_CALL(vpn_service_,
              CreateTunnel(testing::EqualsProto(tunnel_data_string)))
      .Times(0);
  tunnel_manager.StartSession();
  ASSERT_OK(tunnel_manager.RecreateTunnelIfNeeded());
  ASSERT_THAT(tunnel_manager.active_tunnel_test_only(), nullptr);
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
