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

#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker.h"

#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

class MockNotification : public MtuTrackerInterface::NotificationInterface {
 public:
  MOCK_METHOD(void, UplinkMtuUpdated, (int, int), (override));
  MOCK_METHOD(void, DownlinkMtuUpdated, (int), (override));
};

class MtuTrackerTest : public ::testing::Test {
 public:
  MtuTrackerTest() : looper_("MtuTrackerTest Looper") {}

  MockNotification notification_;
  utils::LooperThread looper_;
};

TEST_F(MtuTrackerTest, TestCreateMtuTrackerIPv4) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1395);
}

TEST_F(MtuTrackerTest, TestCreateMtuTrackerIPv6) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv6);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1423);
}

TEST_F(MtuTrackerTest, TestSetNotificationHandlerIPv4) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, 1395))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestSetNotificationHandlerIPv6) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, 1423))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv6);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestCreateWithInitialMtuIPv4) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(2000, 1895))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(2000))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4, 2000);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestCreateWithInitialMtuIPv6) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(2000, 1923))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(2000))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv6, 2000);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestSetLowerUplinkMtu) {
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, 1395)).Times(1);

  absl::Notification uplink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1499, 1394))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);
  mtu_tracker.UpdateUplinkMtu(1499);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestSetHigherUplinkMtu) {
  EXPECT_CALL(notification_, UplinkMtuUpdated(1501, 1396)).Times(0);
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, 1395)).Times(1);

  absl::Notification uplink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1499, 1394))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);
  mtu_tracker.UpdateUplinkMtu(1501);
  mtu_tracker.UpdateUplinkMtu(1499);

  EXPECT_TRUE(uplink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestSetLowerDownlinkMtu) {
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500)).Times(1);

  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1499))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);
  mtu_tracker.UpdateDownlinkMtu(1499);

  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

TEST_F(MtuTrackerTest, TestSetHigherDownlinkMtu) {
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500)).Times(1);

  EXPECT_CALL(notification_, DownlinkMtuUpdated(1501)).Times(0);

  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1499))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification_, &looper_);
  mtu_tracker.UpdateDownlinkMtu(1501);
  mtu_tracker.UpdateDownlinkMtu(1499);

  EXPECT_TRUE(downlink_mtu_updated.WaitForNotificationWithTimeout(
      absl::Milliseconds(100)));
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
