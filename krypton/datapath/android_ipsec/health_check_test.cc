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

#include "privacy/net/krypton/datapath/android_ipsec/health_check.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::status::StatusIs;

class MockNotification : public HealthCheck::NotificationInterface {
 public:
  MOCK_METHOD(void, HealthCheckFailed, (const absl::Status &), (override));
  MOCK_METHOD(void, HealthCheckStarting, (), (override));
  MOCK_METHOD(void, HealthCheckSucceeded, (), (override));
};

class HealthCheckTest : public ::testing::Test {
 public:
  HealthCheckTest()
      : timer_manager_(&mock_timer_interface_),
        looper_("HealthCheckTest Looper") {}

 protected:
  MockTimerInterface mock_timer_interface_;
  TimerManager timer_manager_;
  MockNotification mock_notification_;
  utils::LooperThread looper_;
};

TEST_F(HealthCheckTest, HealthCheckDisabled) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(false);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithoutDuration) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithInvalidDuration) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(315576000001);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithEmptyUrl) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("");
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithValidConfig) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  int expected_timer_id;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id = timer_id;
            return absl::OkStatus();
          });

  health_check.Start();

  EXPECT_CALL(mock_timer_interface_, CancelTimer(expected_timer_id));

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckFailsToStartTimer) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  int expected_timer_id;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id = timer_id;
            return absl::InternalError("Failure");
          });

  health_check.Start();

  // If the StartTimer call fails then CancelTimer should not be called.
  EXPECT_CALL(mock_timer_interface_, CancelTimer(expected_timer_id)).Times(0);

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckStartedTwice) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  int expected_timer_id1;
  int expected_timer_id2;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id1](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id1 = timer_id;
            return absl::OkStatus();
          })
      .WillOnce(
          [&expected_timer_id2](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id2 = timer_id;
            return absl::OkStatus();
          });

  health_check.Start();

  // Second start should cancel the first timer.
  EXPECT_CALL(mock_timer_interface_, CancelTimer(expected_timer_id1));

  health_check.Start();

  // Second timer should be canceled by the Stop.
  EXPECT_CALL(mock_timer_interface_, CancelTimer(expected_timer_id2));

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckPass) {
  int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

  ASSERT_GE(sockfd, 0);

  absl::Cleanup cleanup = [sockfd] { close(sockfd); };

  sockaddr_in6 addr = {};
  socklen_t addr_size = sizeof(addr);
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  ASSERT_EQ(bind(sockfd, reinterpret_cast<sockaddr *>(&addr), addr_size), 0);

  // Read the addr to figure out which port the socket is bound to.
  getsockname(sockfd, reinterpret_cast<sockaddr *>(&addr), &addr_size);

  ASSERT_EQ(listen(sockfd, /*n=*/1), 0);

  utils::LooperThread server_looper("HealthCheckTest Server Looper");
  server_looper.Post([sockfd] {
    int clientfd = accept(sockfd, /*addr=*/nullptr, /*addr_len=*/nullptr);
    EXPECT_GE(clientfd, 0);
    close(clientfd);
  });

  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("localhost");
  config.set_periodic_health_check_port(ntohs(addr.sin6_port));

  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  // Two calls should be seen since the passing check will start the next timer.
  int expected_timer_id;
  absl::Notification timer_started;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id = timer_id;
            return absl::OkStatus();
          })
      .WillOnce([&timer_started]() {
        timer_started.Notify();
        return absl::OkStatus();
      });

  health_check.Start();
  EXPECT_CALL(mock_notification_, HealthCheckStarting()).Times(1);
  EXPECT_CALL(mock_notification_, HealthCheckSucceeded()).Times(1);
  EXPECT_CALL(mock_notification_, HealthCheckFailed(_)).Times(0);
  mock_timer_interface_.TimerExpiry(expected_timer_id);

  ASSERT_TRUE(timer_started.WaitForNotificationWithTimeout(absl::Seconds(1)));

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckFail) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);

  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  int expected_timer_id;
  absl::Notification failed;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id = timer_id;
            return absl::OkStatus();
          });

  health_check.Start();

  EXPECT_CALL(mock_notification_,
              HealthCheckFailed(StatusIs(absl::StatusCode::kInternal)))
      .WillOnce([&failed]() { failed.Notify(); });

  mock_timer_interface_.TimerExpiry(expected_timer_id);

  ASSERT_TRUE(failed.WaitForNotificationWithTimeout(absl::Seconds(1)));

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckGetDebugLogs) {
  // Tests the debug info contains a correct record of the number of network
  // switches occurring between health checks.
  int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
  ASSERT_GE(sockfd, 0);

  absl::Cleanup cleanup = [sockfd] { close(sockfd); };
  sockaddr_in6 addr = {};
  socklen_t addr_size = sizeof(addr);
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  ASSERT_EQ(bind(sockfd, reinterpret_cast<sockaddr *>(&addr), addr_size), 0);

  // Read the addr to figure out which port the socket is bound to.
  getsockname(sockfd, reinterpret_cast<sockaddr *>(&addr), &addr_size);
  ASSERT_EQ(listen(sockfd, /*n=*/1), 0);

  utils::LooperThread server_looper("HealthCheckTest Server Looper");
  server_looper.Post([sockfd] {
    int clientfd = accept(sockfd, /*addr=*/nullptr, /*addr_len=*/nullptr);
    EXPECT_GE(clientfd, 0);
    close(clientfd);
  });

  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("localhost");
  config.set_periodic_health_check_port(ntohs(addr.sin6_port));

  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  // No Health Check debug info should exist before first health check.
  DatapathDebugInfo debug_info;
  health_check.GetDebugInfo(&debug_info);
  ASSERT_EQ(debug_info.health_check_results().size(), 0);

  // Each time a health check timer expires, a health check is performed. If the
  // health check passes, a new timer is started. Here StartTimer() is called
  // three times and the timer expires twice before the health check is stopped.
  // The result is two health checks being performed.
  int expected_timer_id;
  int expected_timer_id2;
  absl::Notification timer_started;
  absl::Notification timer_started2;
  EXPECT_CALL(mock_timer_interface_, StartTimer(_, Eq(absl::Seconds(1))))
      .WillOnce(
          [&expected_timer_id](int timer_id, absl::Duration /*duration*/) {
            expected_timer_id = timer_id;
            return absl::OkStatus();
          })
      .WillOnce([&expected_timer_id2, &timer_started](
                    int timer_id, absl::Duration /*duration*/) {
        // Expected_timer_id2 is used in the TimerExpiry() call below, after
        // WaitForNotificationWithTimeout() completes. If this function calls
        // Notify() before the timer id value is assigned, there is a data race.
        // That is because the timer id's value is being assigned in this scope
        // while the same variable is used in the TimerExpiry() call below.
        absl::Cleanup notify = [&timer_started] { timer_started.Notify(); };
        expected_timer_id2 = timer_id;
        return absl::OkStatus();
      })
      .WillOnce([&timer_started2]() {
        // As there is no timer id value assignment in this lambda, Notify() may
        // be called at the start of the function.
        timer_started2.Notify();
        return absl::OkStatus();
      });

  health_check.Start();
  EXPECT_CALL(mock_notification_, HealthCheckFailed(_)).Times(0);

  // Two network switches before first health check completes.
  health_check.IncrementNetworkSwitchCounter();
  health_check.IncrementNetworkSwitchCounter();
  mock_timer_interface_.TimerExpiry(expected_timer_id);
  ASSERT_TRUE(timer_started.WaitForNotificationWithTimeout(absl::Seconds(1)));

  // No network switches between first and second health check completions.
  mock_timer_interface_.TimerExpiry(expected_timer_id2);
  ASSERT_TRUE(timer_started2.WaitForNotificationWithTimeout(absl::Seconds(1)));
  health_check.Stop();

  health_check.GetDebugInfo(&debug_info);
  ASSERT_EQ(debug_info.health_check_results().size(), 2);
  // Verify results from first health check.
  EXPECT_EQ(debug_info.health_check_results().at(0).health_check_successful(),
            true);
  EXPECT_EQ(debug_info.health_check_results()
                .at(0)
                .network_switches_since_health_check(),
            2);
  // Verify results from second health check.
  EXPECT_EQ(debug_info.health_check_results()
                .at(1)
                .network_switches_since_health_check(),
            0);
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
