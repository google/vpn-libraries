// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/reconnector.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/mock_notification_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "testing/base/public/mock-log.h"
#include "third_party/absl/base/log_severity.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::EqualsProto;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::status::StatusIs;

constexpr char kExpectedConfig[] = R"pb(
  zinc_url: "https://autopush.zinc"
  brass_url: "https://autopush.brass"
  service_type: "g1"
)pb";

class MockSessionNotification : public Session::NotificationInterface {
 public:
  MOCK_METHOD(void, ControlPlaneConnected, (), (override));
  MOCK_METHOD(void, StatusUpdated, (), (override));
  MOCK_METHOD(void, ControlPlaneDisconnected, (const absl::Status&),
              (override));
  MOCK_METHOD(void, PermanentFailure, (const absl::Status&), (override));
  MOCK_METHOD(void, DatapathConnected, (), (override));
  MOCK_METHOD(void, DatapathDisconnected,
              (const NetworkInfo& network, const absl::Status&), (override));
};

class MockSessionManagerInterface : public SessionManagerInterface {
 public:
  MOCK_METHOD(void, RegisterNotificationInterface,
              (Session::NotificationInterface*), (override));
  MOCK_METHOD(void, EstablishSession,
              (int, TunnelManagerInterface*, std::optional<NetworkInfo>),
              (override));
  MOCK_METHOD(void, TerminateSession, (bool), (override));
  MOCK_METHOD(std::optional<Session*>, session, (), (const, override));
};

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

// Test class for Reconnector.
class ReconnectorTest : public ::testing::Test {
 public:
  void SetUp() override {
    KryptonConfig config;
    config.set_zinc_url("https://autopush.zinc");
    config.set_brass_url("https://autopush.brass");
    config.set_service_type("g1");

    notification_thread_ =
        std::make_unique<utils::LooperThread>("ReconnectorTest Looper");

    fake_clock_.SetNow(absl::FromUnixSeconds(fake_clock_now_));

    reconnector_ = std::make_unique<Reconnector>(
        &timer_manager_, config, &session_manager_, &tunnel_manager_,
        notification_thread_.get(), &fake_clock_);
    reconnector_->RegisterNotificationInterface(
        &krypton_notification_interface_);
  }

  // Returns the connection deadline timer_id;
  void InitialExpectations(int* timer_id) {
    EXPECT_CALL(session_manager_,
                EstablishSession(
                    /*restart_count=*/0, &tunnel_manager_, Eq(std::nullopt)));
    ExpectStartTimer(absl::Seconds(30), timer_id);
  }

  void ExpectStartTimer(absl::Duration duration, int* timer_id) {
    EXPECT_CALL(timer_interface_, StartTimer(_, duration))
        .WillOnce(DoAll(SaveArg<0>(timer_id), Return(absl::OkStatus())));
  }

  void WaitForNotifications() {
    absl::Mutex lock;
    absl::CondVar condition;
    absl::MutexLock l(&lock);
    notification_thread_->Post([&condition] { condition.SignalAll(); });
    condition.Wait(&lock);
  }

 protected:
  MockNotification krypton_notification_interface_;
  MockSessionManagerInterface session_manager_;
  MockTunnelManager tunnel_manager_;
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};
  std::unique_ptr<Reconnector> reconnector_;
  std::unique_ptr<utils::LooperThread> notification_thread_;
  const int64_t fake_clock_now_ = 1764328000L;
  FakeClock fake_clock_ = FakeClock(absl::FromUnixSeconds(fake_clock_now_));
};

TEST_F(ReconnectorTest, InitialSessionCreation) {
  int timer_id;
  InitialExpectations(&timer_id);

  reconnector_->Start();
}

TEST_F(ReconnectorTest,
       InitialConnectionDeadlineFailureAndRaceWithDisconnectedEvent) {
  int connection_deadline_timer_id;
  int reconnection_timer_id;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  // Clear all timer expecations.
  ::testing::Mock::VerifyAndClearExpectations(&timer_interface_);

  // expect terminating a session and start a reconnect timer id.
  EXPECT_CALL(session_manager_, TerminateSession);
  ExpectStartTimer(absl::Seconds(2), &reconnection_timer_id);
  EXPECT_EQ(reconnector_->state(),
            Reconnector::State::kWaitingForSessionEstablishment);

  timer_interface_.TimerExpiry(connection_deadline_timer_id);
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kWaitingToReconnect);
}

TEST_F(ReconnectorTest, CancelDeadlineTimerOnConnected) {
  int connection_deadline_timer_id;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);
}

TEST_F(ReconnectorTest, CheckExponentialBackOff) {
  int connection_deadline_timer_id;
  int session_reconnect_count = 0;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  reconnector_->ControlPlaneConnected();

  // Clear all timer expectations.
  ::testing::Mock::VerifyAndClearExpectations(&timer_interface_);

  int reconnect_time_id;
  int reconnect_time_secs = 1;

  // Start with 1 as successive control plane failures will be incremented to 1
  // after receiving |ControlPlaneDisconnected|.
  for (int i = 1; i < 10; i++) {
    reconnect_time_secs = std::pow(2, i);
    ExpectStartTimer(absl::Seconds(reconnect_time_secs), &reconnect_time_id);
    EXPECT_CALL(session_manager_, TerminateSession);
    reconnector_->ControlPlaneDisconnected(absl::NotFoundError("Some status"));

    EXPECT_CALL(session_manager_,
                EstablishSession(++session_reconnect_count, &tunnel_manager_,
                                 Eq(std::nullopt)));
    ExpectStartTimer(absl::Seconds(30), &connection_deadline_timer_id);
    timer_interface_.TimerExpiry(reconnect_time_id);
  }
}

TEST_F(ReconnectorTest, ResetFailureCountersWhenSetNetworkCalled) {
  int connection_deadline_timer_id;
  int session_reconnect_count = 0;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  reconnector_->ControlPlaneConnected();

  // Clear all timer expectations.
  ::testing::Mock::VerifyAndClearExpectations(&timer_interface_);

  // Simulate a control plane failure.
  int reconnect_time_id;
  ExpectStartTimer(absl::Seconds(2), &reconnect_time_id);
  EXPECT_CALL(session_manager_, TerminateSession);
  reconnector_->ControlPlaneDisconnected(absl::NotFoundError("Some status"));

  EXPECT_CALL(session_manager_,
              EstablishSession(++session_reconnect_count, &tunnel_manager_,
                               Eq(std::nullopt)));
  ExpectStartTimer(absl::Seconds(30), &connection_deadline_timer_id);
  timer_interface_.TimerExpiry(reconnect_time_id);
  EXPECT_EQ(1, reconnector_->SuccessiveControlplaneFailuresTestOnly());

  // SetNetwork should reset the failure counters.
  EXPECT_OK(reconnector_->SetNetwork(NetworkInfo()));
  EXPECT_EQ(0, reconnector_->SuccessiveControlplaneFailuresTestOnly());
  EXPECT_EQ(0, reconnector_->SuccessiveDatapathFailuresTestOnly());
}

TEST_F(ReconnectorTest, PopulatesDebugInfo) {
  reconnector_->Start();

  ReconnectorDebugInfo debug_info;
  reconnector_->GetDebugInfo(&debug_info);

  EXPECT_THAT(debug_info, EqualsProto(R"pb(
                state: "WaitingForSessionEstablishment"
                session_restart_counter: 1
                successive_control_plane_failures: 1
                successive_data_plane_failures: 1
              )pb"));
}

TEST_F(ReconnectorTest, TestAirplaneModeOn) {
  int connection_deadline_timer_id;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession);
  EXPECT_CALL(krypton_notification_interface_, Disconnected);
  EXPECT_OK(reconnector_->SetNetwork(std::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kPaused);
}

TEST_F(ReconnectorTest, TestAirplaneModeOff) {
  int connection_deadline_timer_id;
  int reconnect_time_id = 0;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession);
  // Go to Airplane mode.
  EXPECT_OK(reconnector_->SetNetwork(std::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kPaused);

  // Turn Airplane mode off
  ExpectStartTimer(absl::Seconds(1), &reconnect_time_id);
  EXPECT_CALL(session_manager_, TerminateSession);
  timer_interface_.TimerExpiry(reconnect_time_id);

  EXPECT_OK(reconnector_->SetNetwork(NetworkInfo()));
  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/1, &tunnel_manager_, _));
  ExpectStartTimer(absl::Seconds(30), &reconnect_time_id);

  // This will start the session establishment.
  timer_interface_.TimerExpiry(reconnect_time_id);
}

TEST_F(ReconnectorTest, TestSnooze) {
  int connection_deadline_timer_id;
  int snooze_timer_id = 0;
  absl::Duration snooze_duration_mins = absl::Minutes(1);

  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession(/*forceFailOpen=*/true));
  ExpectStartTimer(snooze_duration_mins, &snooze_timer_id);
  timer_interface_.TimerExpiry(snooze_timer_id);
  EXPECT_CALL(krypton_notification_interface_, Snoozed);
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);
}

TEST_F(ReconnectorTest, TestResumeSnoozeTimerExpired) {
  int connection_deadline_timer_id;
  int snooze_timer_id;
  absl::Duration snooze_duration_mins = absl::Minutes(1);

  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/0, &tunnel_manager_, _));
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(30)))
      .WillRepeatedly(DoAll(SaveArg<0>(&connection_deadline_timer_id),
                            Return(absl::OkStatus())));
  reconnector_->Start();

  ExpectStartTimer(snooze_duration_mins, &snooze_timer_id);
  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession(/*forceFailOpen=*/true));
  EXPECT_CALL(krypton_notification_interface_, Resumed);
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/1, &tunnel_manager_, _));

  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id)).Times(1);
  timer_interface_.TimerExpiry(snooze_timer_id);
}

TEST_F(ReconnectorTest, TestResumeWhenTimerNotExpired) {
  int connection_deadline_timer_id;
  int snooze_timer_id;
  absl::Duration snooze_duration_mins = absl::Minutes(1);

  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/0, &tunnel_manager_, _));
  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Seconds(30)))
      .WillRepeatedly(DoAll(SaveArg<0>(&connection_deadline_timer_id),
                            Return(absl::OkStatus())));
  reconnector_->Start();

  ExpectStartTimer(snooze_duration_mins, &snooze_timer_id);
  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession(/*forceFailOpen=*/true));
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/1, &tunnel_manager_, _));

  // If Resume() is not triggered automatically, we would like to cancel the
  // timer that will automatically trigger Resume().
  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id)).Times(1);
  EXPECT_OK(reconnector_->Resume());
  // Should not trigger Resume again.
  timer_interface_.TimerExpiry(snooze_timer_id);
}

TEST_F(ReconnectorTest, TestResumeCreateTempTunnelForSafeDisconnect) {
  absl::Duration snooze_duration_mins = absl::Minutes(1);
  tunnel_manager_.SetSafeDisconnectEnabled(/*enabled=*/true);
  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/0, &tunnel_manager_, _));
  reconnector_->Start();
  reconnector_->ControlPlaneConnected();
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_CALL(session_manager_, EstablishSession(
                                    /*restart_count=*/1, &tunnel_manager_, _));
  EXPECT_CALL(tunnel_manager_, RecreateTunnelIfNeeded);
  EXPECT_OK(reconnector_->Resume());
}

TEST_F(ReconnectorTest, TestStopSnoozeTimerWhenStopped) {
  int connection_deadline_timer_id;
  int snooze_timer_id = 0;
  absl::Duration snooze_duration_mins = absl::Minutes(1);

  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession).Times(2);
  ExpectStartTimer(snooze_duration_mins, &snooze_timer_id);
  timer_interface_.TimerExpiry(snooze_timer_id);
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id));
  reconnector_->Stop();
  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id)).Times(0);
  timer_interface_.TimerExpiry(snooze_timer_id);
}

TEST_F(ReconnectorTest, TestResumeNoOpWhenNotSnoozed) {
  int connection_deadline_timer_id;

  InitialExpectations(&connection_deadline_timer_id);
  reconnector_->Start();

  // If PPN is not snoozed, then there is no point in resumed it.
  EXPECT_THAT(reconnector_->Resume(),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       "Cannot resume PPN because it is not snoozed."));
}

TEST_F(ReconnectorTest, TestSnoozeNoOpWhenInPermanentFailure) {
  reconnector_->PermanentFailure(absl::OkStatus());

  // If in a kPermanentFailure state, we do not want to snooze.
  EXPECT_THAT(
      reconnector_->Snooze(absl::Minutes(1)),
      StatusIs(absl::StatusCode::kFailedPrecondition,
               "Krypton is in state PermanentFailure. Refusing to snooze."));
}

// If PPN is trying to reconnect due to service interruption and it is
// kSnoozed, we will stop reconnection until we exit kSnoozed state.
// Once we exit kSnoozed state, we will let system handle reconnection
// after Start() method is called.
TEST_F(ReconnectorTest, TestSnoozeOnCancelReconnection) {
  int connection_deadline_timer_id;
  int reconnect_time_id;
  int snooze_timer_id;
  absl::Duration snooze_duration_mins = absl::Minutes(1);
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  // Go to Airplane mode.
  EXPECT_OK(reconnector_->SetNetwork(std::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kPaused);

  // Setting network while in Airplane mode to initiate reconnection.
  ExpectStartTimer(absl::Seconds(1), &reconnect_time_id);
  EXPECT_OK(reconnector_->SetNetwork(NetworkInfo()));

  // Transitioning to kSnoozed.
  EXPECT_CALL(timer_interface_, CancelTimer(reconnect_time_id));
  ExpectStartTimer(snooze_duration_mins, &snooze_timer_id);
  EXPECT_OK(reconnector_->Snooze(snooze_duration_mins));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);
}

// If PPN is in kSnoozed state,
TEST_F(ReconnectorTest, TestSnoozeSetNetworkNoOp) {
  EXPECT_OK(reconnector_->Snooze(absl::Minutes(1)));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  // If in kSnoozed state, nothing should be done (i.e. TerminateSession
  // should not be called) when SetNetwork() is called.
  EXPECT_CALL(timer_interface_, StartTimer).Times(0);
  EXPECT_CALL(session_manager_, TerminateSession).Times(0);
  EXPECT_OK(reconnector_->SetNetwork(std::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  EXPECT_OK(reconnector_->SetNetwork(NetworkInfo()));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);
}

TEST_F(ReconnectorTest, TestExtendSnooze) {
  int connection_deadline_timer_id;
  int snooze_timer_id;
  absl::Duration snooze_duration = absl::Seconds(300);
  absl::Duration already_snoozed_duration = absl::Seconds(125);
  absl::Duration extend_snooze_duration = absl::Seconds(600);

  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  ExpectStartTimer(snooze_duration, &snooze_timer_id);
  EXPECT_OK(reconnector_->Snooze(snooze_duration));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kSnoozed);

  fake_clock_.AdvanceBy(already_snoozed_duration);
  absl::Duration expected_snooze_duration_1 =
      snooze_duration - already_snoozed_duration + extend_snooze_duration;

  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id));
  ExpectStartTimer(expected_snooze_duration_1, &snooze_timer_id);
  EXPECT_OK(reconnector_->ExtendSnooze(extend_snooze_duration));

  fake_clock_.AdvanceBy(already_snoozed_duration * 2);
  absl::Duration expected_snooze_duration_2 = expected_snooze_duration_1 -
                                              already_snoozed_duration * 2 +
                                              extend_snooze_duration;

  EXPECT_CALL(timer_interface_, CancelTimer(snooze_timer_id));
  ExpectStartTimer(expected_snooze_duration_2, &snooze_timer_id);
  EXPECT_OK(reconnector_->ExtendSnooze(extend_snooze_duration));
}

TEST_F(ReconnectorTest, TestExtendSnoozeNoOpIfNotSnoozed) {
  int connection_deadline_timer_id;
  absl::Duration extend_snooze_duration = absl::Minutes(1);

  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_THAT(
      reconnector_->ExtendSnooze(extend_snooze_duration),
      StatusIs(
          absl::StatusCode::kFailedPrecondition,
          "Unable to extend snooze duration since Krypton is not Snoozed."));
}

class DatapathReconnectorTest : public ReconnectorTest {
 public:
  void SetUp() override {
    KryptonConfig config;
    config.set_zinc_url("https://autopush.zinc");
    config.set_brass_url("https://autopush.brass");
    config.set_service_type("g1");

    notification_thread_ =
        std::make_unique<utils::LooperThread>("ReconnectorTest Looper");

    reconnector_ = std::make_unique<Reconnector>(
        &timer_manager_, config, &session_manager_, &tunnel_manager_,
        notification_thread_.get(), &fake_clock_);
    reconnector_->RegisterNotificationInterface(
        &krypton_notification_interface_);

    int connection_deadline_timer_id;
    InitialExpectations(&connection_deadline_timer_id);

    reconnector_->Start();

    EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
    reconnector_->ControlPlaneConnected();
    EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);
  }
};

TEST_F(DatapathReconnectorTest, TestDatapathSuccessful) {
  reconnector_->DatapathConnected();
  EXPECT_EQ(0, reconnector_->SuccessiveDatapathFailuresTestOnly());
  EXPECT_EQ(0, reconnector_->SuccessiveControlplaneFailuresTestOnly());
  EXPECT_EQ(-1, reconnector_->DatapathWatchdogTimerIdTestOnly());
}

TEST_F(DatapathReconnectorTest, TestDatapathWatchtimerIsRunning) {
  int datapath_timer_id;
  ExpectStartTimer(absl::Seconds(2), &datapath_timer_id);
  reconnector_->DatapathDisconnected(NetworkInfo(),
                                     absl::FailedPreconditionError("testing"));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);
  EXPECT_EQ(1, reconnector_->SuccessiveDatapathFailuresTestOnly());
}

TEST_F(DatapathReconnectorTest, TestMultipleDatapathDisconnectNotifications) {
  int datapath_timer_id;
  ExpectStartTimer(absl::Seconds(2), &datapath_timer_id);
  reconnector_->DatapathDisconnected(NetworkInfo(),
                                     absl::FailedPreconditionError("testing"));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);
  EXPECT_EQ(1, reconnector_->SuccessiveDatapathFailuresTestOnly());

  EXPECT_CALL(timer_interface_, CancelTimer(datapath_timer_id));
  ExpectStartTimer(absl::Seconds(2), &datapath_timer_id);
  reconnector_->DatapathDisconnected(NetworkInfo(),
                                     absl::FailedPreconditionError("testing"));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);
  EXPECT_EQ(2, reconnector_->SuccessiveDatapathFailuresTestOnly());
}

TEST_F(DatapathReconnectorTest, TestDatapathReconnectorReattempts) {
  int reconnect_time_id;
  // int reconnect_time_secs = 1;
  int connection_deadline_timer_id;
  int session_reconnect_count = 0;

  for (int i = 1; i < 3; i++) {
    int datapath_timer_id;
    ExpectStartTimer(absl::Seconds(2), &datapath_timer_id);
    absl::Status status = absl::DeadlineExceededError("Waiting to reconnect");

    EXPECT_CALL(krypton_notification_interface_, Disconnected(_)).Times(2);
    reconnector_->DatapathDisconnected(NetworkInfo(), status);

    // Datapath watchdog expiry will result in termination of the session and
    // starting the timer.
    ExpectStartTimer(absl::Seconds(std::pow(2, i)), &reconnect_time_id);
    EXPECT_CALL(session_manager_, TerminateSession);
    timer_interface_.TimerExpiry(datapath_timer_id);

    // Reconnection timer expiry.
    ExpectStartTimer(absl::Seconds(30), &connection_deadline_timer_id);
    EXPECT_CALL(session_manager_,
                EstablishSession(++session_reconnect_count, &tunnel_manager_,
                                 Eq(std::nullopt)));

    timer_interface_.TimerExpiry(reconnect_time_id);

    // Session moving to connected.
    WaitForNotifications();
    EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
    reconnector_->ControlPlaneConnected();
  }
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
