// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/reconnector.h"

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/pal/mock_notification_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager_interface.h"
#include "privacy/net/krypton/timer_manager.h"
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
using ::testing::HasSubstr;
using ::testing::kDoNotCaptureLogsYet;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::ScopedMockLog;

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
              (absl::string_view, absl::string_view, absl::string_view, int,
               absl::optional<NetworkInfo>),
              (override));
  MOCK_METHOD(void, TerminateSession, (), (override));
  MOCK_METHOD(absl::optional<Session*>, session, (), (const, override));
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

    reconnector_ = absl::make_unique<Reconnector>(
        &timer_manager_, config, &session_manager_, notification_thread_.get());
    reconnector_->RegisterNotificationInterface(
        &krypton_notification_interface_);
  }

  // Returns the connection deadline timer_id;
  void InitialExpectations(int* timer_id) {
    EXPECT_CALL(session_manager_,
                EstablishSession("https://autopush.zinc",
                                 "https://autopush.brass", "g1",
                                 /*restart_count=*/0, Eq(absl::nullopt)));
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
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};
  std::unique_ptr<Reconnector> reconnector_;
  std::unique_ptr<utils::LooperThread> notification_thread_;
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

  // Clear all timer expecations.
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

    EXPECT_CALL(
        session_manager_,
        EstablishSession("https://autopush.zinc", "https://autopush.brass",
                         "g1", ++session_reconnect_count, Eq(absl::nullopt)));
    ExpectStartTimer(absl::Seconds(30), &connection_deadline_timer_id);
    timer_interface_.TimerExpiry(reconnect_time_id);
  }
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
  EXPECT_OK(reconnector_->SetNetwork(absl::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kPaused);
}

TEST_F(ReconnectorTest, TestAirplaneModeOff) {
  int connection_deadline_timer_id;
  int reconnect_time_id;
  InitialExpectations(&connection_deadline_timer_id);

  reconnector_->Start();

  EXPECT_CALL(timer_interface_, CancelTimer(connection_deadline_timer_id));
  EXPECT_CALL(krypton_notification_interface_, ControlPlaneConnected);
  reconnector_->ControlPlaneConnected();
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kConnected);

  EXPECT_CALL(session_manager_, TerminateSession);
  // Go to Airplane mode.
  EXPECT_OK(reconnector_->SetNetwork(absl::nullopt));
  EXPECT_EQ(reconnector_->state(), Reconnector::State::kPaused);

  // Turn Airplane mode off
  ExpectStartTimer(absl::Seconds(1), &reconnect_time_id);
  EXPECT_CALL(session_manager_, TerminateSession);
  timer_interface_.TimerExpiry(reconnect_time_id);

  EXPECT_OK(reconnector_->SetNetwork(NetworkInfo()));
  EXPECT_CALL(session_manager_, EstablishSession("https://autopush.zinc",
                                                 "https://autopush.brass", "g1",
                                                 /*restart_count=*/1, _));
  ExpectStartTimer(absl::Seconds(30), &reconnect_time_id);

  // This will start the session establishment.
  timer_interface_.TimerExpiry(reconnect_time_id);
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

    reconnector_ = absl::make_unique<Reconnector>(
        &timer_manager_, config, &session_manager_, notification_thread_.get());
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
    absl::Status status =
        absl::FailedPreconditionError(absl::StrCat("Testing ", i));

    EXPECT_CALL(krypton_notification_interface_, Disconnected(status));
    reconnector_->DatapathDisconnected(NetworkInfo(), status);

    // Datapath watchdog expiry will result in termination of the session and
    // starting the timer.
    ExpectStartTimer(absl::Seconds(std::pow(2, i)), &reconnect_time_id);
    EXPECT_CALL(session_manager_, TerminateSession);
    timer_interface_.TimerExpiry(datapath_timer_id);

    // Reconnection timer expiry.
    ExpectStartTimer(absl::Seconds(30), &connection_deadline_timer_id);
    EXPECT_CALL(
        session_manager_,
        EstablishSession("https://autopush.zinc", "https://autopush.brass",
                         "g1", ++session_reconnect_count, Eq(absl::nullopt)));

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
