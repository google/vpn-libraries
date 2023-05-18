// Copyright 2023 Google LLC
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

#include "privacy/net/krypton/session_manager.h"

#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace {

using ::testing::_;

class MockTunnelManager : public TunnelManagerInterface {
 public:
  MOCK_METHOD(absl::Status, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, SetSafeDisconnectEnabled, (bool), (override));
  MOCK_METHOD(bool, IsSafeDisconnectEnabled, (), (override));
  MOCK_METHOD(void, StartSession, (), (override));
  MOCK_METHOD(absl::Status, EnsureTunnelIsUp, (TunFdData), (override));
  MOCK_METHOD(absl::Status, RecreateTunnelIfNeeded, (), (override));
  MOCK_METHOD(void, TerminateSession, (bool), (override));
  MOCK_METHOD(bool, IsTunnelActive, (), (override));
};

class MockDatapath : public DatapathInterface {
 public:
  MOCK_METHOD(absl::Status, Start,
              (const AddEgressResponse&, const TransformParams& params),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, RegisterNotificationHandler,
              (DatapathInterface::NotificationInterface * notification),
              (override));
  MOCK_METHOD(absl::Status, SwitchNetwork,
              (uint32_t, const Endpoint&, std::optional<NetworkInfo>, int),
              (override));
  MOCK_METHOD(void, PrepareForTunnelSwitch, (), (override));
  MOCK_METHOD(void, SwitchTunnel, (), (override));
  MOCK_METHOD(absl::Status, SetKeyMaterials, (const TransformParams&),
              (override));
  MOCK_METHOD(void, GetDebugInfo, (DatapathDebugInfo*), (override));
};

class SessionManagerTest : public ::testing::Test {
 public:
  SessionManagerTest()
      : timer_manager_(&mock_timer_),
        notification_thread_("SessionManagerTest Looper"),
        session_manager_(config_, &mock_http_fetcher_, &timer_manager_,
                         &mock_vpn_service_, &mock_oauth_,
                         &mock_tunnel_manager_, &notification_thread_) {}

 protected:
  KryptonConfig config_;
  MockHttpFetcher mock_http_fetcher_;
  MockTimerInterface mock_timer_;
  TimerManager timer_manager_;
  MockVpnService mock_vpn_service_;
  MockOAuth mock_oauth_;
  MockTunnelManager mock_tunnel_manager_;
  utils::LooperThread notification_thread_;
  SessionManager session_manager_;
};

TEST_F(SessionManagerTest, EstablishSessionStartsSession) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _)).WillOnce([] {
    return new MockDatapath();
  });
  EXPECT_CALL(mock_tunnel_manager_, StartSession());
  EXPECT_CALL(mock_tunnel_manager_, TerminateSession(false));

  session_manager_.EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                    NetworkInfo());

  session_manager_.TerminateSession(false);
}

TEST_F(SessionManagerTest, SecondEstablishSessionTerminatesOldSession) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _))
      .Times(2)
      .WillRepeatedly([] { return new MockDatapath(); });
  EXPECT_CALL(mock_tunnel_manager_, StartSession()).Times(2);
  EXPECT_CALL(mock_tunnel_manager_, TerminateSession(false)).Times(2);

  session_manager_.EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                    NetworkInfo());
  session_manager_.EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                    NetworkInfo());

  session_manager_.TerminateSession(false);
}

TEST_F(SessionManagerTest, SecondTerminateSessionClosesTunnel) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _)).WillOnce([] {
    return new MockDatapath();
  });
  EXPECT_CALL(mock_tunnel_manager_, StartSession());
  EXPECT_CALL(mock_tunnel_manager_, TerminateSession(false));
  EXPECT_CALL(mock_tunnel_manager_, TerminateSession(true));

  session_manager_.EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                    NetworkInfo());

  session_manager_.TerminateSession(false);
  session_manager_.TerminateSession(true);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
