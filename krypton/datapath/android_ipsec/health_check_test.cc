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
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithoutDuration) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithInvalidDuration) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(315576000001);
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithMissingUrl) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_port(80);
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
  config.set_periodic_health_check_port(80);
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithMissingPort) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("www.google.com");
  HealthCheck health_check(config, &timer_manager_, &mock_notification_,
                           &looper_);

  EXPECT_CALL(mock_timer_interface_, StartTimer(_, _)).Times(0);

  health_check.Start();
}

TEST_F(HealthCheckTest, HealthCheckEnabledWithValidConfig) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
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
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
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
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);
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

  EXPECT_CALL(mock_notification_, HealthCheckFailed(_)).Times(0);

  mock_timer_interface_.TimerExpiry(expected_timer_id);

  timer_started.WaitForNotificationWithTimeout(absl::Seconds(1));

  health_check.Stop();
}

TEST_F(HealthCheckTest, HealthCheckFail) {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(1);
  config.set_periodic_health_check_url("www.google.com");
  config.set_periodic_health_check_port(80);

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

  failed.WaitForNotificationWithTimeout(absl::Seconds(1));

  health_check.Stop();
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
