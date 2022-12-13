/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/windows/ppn_telemetry_manager.h"

#include <memory>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

using ::testing::_;

class MockKrypton : public Krypton {
 public:
  MockKrypton() : Krypton(nullptr, nullptr, nullptr, nullptr, nullptr) {}
  MOCK_METHOD(void, CollectTelemetry, (KryptonTelemetry*), ());
};

class PpnTelemetryManagerTest : public ::testing::Test {
  void SetUp() override {
    clock_.SetNow(absl::UniversalEpoch());
    ppn_telemetry_manager_ = std::make_unique<PpnTelemetryManager>(&clock_);
    ON_CALL(krypton_, CollectTelemetry(_)).WillByDefault(testing::Return());
  }

 protected:
  FakeClock clock_ = FakeClock(absl::UniversalEpoch());
  std::unique_ptr<PpnTelemetryManager> ppn_telemetry_manager_;
  MockKrypton krypton_;
};

TEST_F(PpnTelemetryManagerTest, TestCollect_DefaultsToZero) {
  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.ppn_service_uptime().seconds(), 0);
  ASSERT_EQ(telemetry.ppn_connection_uptime().seconds(), 0);
  ASSERT_EQ(telemetry.network_uptime().seconds(), 0);
  ASSERT_EQ(telemetry.disconnection_durations_size(), 0);
  ASSERT_EQ(telemetry.disconnection_count(), 0);
}

TEST_F(PpnTelemetryManagerTest, TestCollect_ReturnsCorrectValues) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStopped();
  clock_.AdvanceBy(absl::Seconds(1));

  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.ppn_service_uptime().seconds(), 5);
  ASSERT_EQ(telemetry.ppn_connection_uptime().seconds(), 1);
  ASSERT_EQ(telemetry.network_uptime().seconds(), 3);
  ASSERT_EQ(telemetry.disconnection_durations_size(), 1);
  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest, TestCollect_ReturnsOneDisconnection) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));

  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.disconnection_durations_size(), 1);
  ASSERT_EQ(telemetry.disconnection_durations(0).seconds(), 1);

  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest,
       TestDisconnectionFollowedByNetworkLossAndReconnect_2Disconnections) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));

  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  auto durations = telemetry.disconnection_durations();
  ASSERT_EQ(telemetry.disconnection_durations_size(), 2);
  ASSERT_EQ(durations.Get(0).seconds(), 1);
  ASSERT_EQ(durations.Get(1).seconds(), 1);
  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest,
       TestDisconnectionFollowedbyNetworkLossesAndReconnect_3Disconnections) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(2));
  ppn_telemetry_manager_->NotifyConnected();

  clock_.AdvanceBy(absl::Seconds(1));

  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  auto durations = telemetry.disconnection_durations();
  ASSERT_EQ(telemetry.disconnection_durations_size(), 3);
  ASSERT_EQ(durations.Get(0).seconds(), 1);
  ASSERT_EQ(durations.Get(1).seconds(), 1);
  ASSERT_EQ(durations.Get(2).seconds(), 2);
  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest,
       TestDisconnectionFollowedByStop_collectsOneDisconnection) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStopped();

  clock_.AdvanceBy(absl::Seconds(1));

  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.disconnection_durations_size(), 1);
  ASSERT_EQ(telemetry.disconnection_durations(0).seconds(), 1);

  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest,
       TestDisconnectionFollowedByNetworkLossAndStop_collectsOneDisconnection) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyDisconnected();
  clock_.AdvanceBy(absl::Seconds(2));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStopped();

  clock_.AdvanceBy(absl::Seconds(1));
  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.disconnection_durations_size(), 1);
  ASSERT_EQ(telemetry.disconnection_durations(0).seconds(), 2);

  ASSERT_EQ(telemetry.disconnection_count(), 1);
}

TEST_F(PpnTelemetryManagerTest,
       TestNoDisconnection_shouldNotCollectDisconnectionSpan) {
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStarted();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyNetworkAvailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyConnected();
  clock_.AdvanceBy(absl::Seconds(2));
  ppn_telemetry_manager_->NotifyNetworkUnavailable();
  clock_.AdvanceBy(absl::Seconds(1));
  ppn_telemetry_manager_->NotifyStopped();

  clock_.AdvanceBy(absl::Seconds(1));
  privacy::krypton::desktop::PpnTelemetry telemetry =
      ppn_telemetry_manager_->Collect(&krypton_);

  ASSERT_EQ(telemetry.disconnection_count(), 0);
  ASSERT_EQ(telemetry.disconnection_durations_size(), 0);
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
