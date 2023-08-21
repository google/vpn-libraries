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

using ::testing::_;

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
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  int notification_uplink_mtu;
  int notification_tunnel_mtu;
  EXPECT_CALL(notification_, UplinkMtuUpdated(_, _))
      .WillOnce([&uplink_mtu_updated, &notification_uplink_mtu,
                 &notification_tunnel_mtu](int uplink_mtu, int tunnel_mtu) {
        notification_uplink_mtu = uplink_mtu;
        notification_tunnel_mtu = tunnel_mtu;
        uplink_mtu_updated.Notify();
      });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(_))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, &notification_, &looper_);

  uplink_mtu_updated.WaitForNotification();
  downlink_mtu_updated.WaitForNotification();

  // Verify that tunnel MTU is accounting for overhead
  EXPECT_GT(notification_uplink_mtu, notification_tunnel_mtu);
}

TEST_F(MtuTrackerTest, TestCreateMtuTrackerIPv6) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  int notification_uplink_mtu;
  int notification_tunnel_mtu;
  EXPECT_CALL(notification_, UplinkMtuUpdated(_, _))
      .WillOnce([&uplink_mtu_updated, &notification_uplink_mtu,
                 &notification_tunnel_mtu](int uplink_mtu, int tunnel_mtu) {
        notification_uplink_mtu = uplink_mtu;
        notification_tunnel_mtu = tunnel_mtu;
        uplink_mtu_updated.Notify();
      });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(_))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv6, &notification_, &looper_);

  uplink_mtu_updated.WaitForNotification();
  downlink_mtu_updated.WaitForNotification();

  // Verify that tunnel MTU is accounting for overhead
  EXPECT_GT(notification_uplink_mtu, notification_tunnel_mtu);
}

TEST_F(MtuTrackerTest, TestCreateWithInitialMtuIPv4) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  int notification_tunnel_mtu;
  EXPECT_CALL(notification_, UplinkMtuUpdated(2000, _))
      .WillOnce([&uplink_mtu_updated, &notification_tunnel_mtu](
                    int /*uplink_mtu*/, int tunnel_mtu) {
        notification_tunnel_mtu = tunnel_mtu;
        uplink_mtu_updated.Notify();
      });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(2000))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, 2000, &notification_, &looper_);

  uplink_mtu_updated.WaitForNotification();
  downlink_mtu_updated.WaitForNotification();

  // Verify that tunnel MTU is accounting for overhead
  EXPECT_GT(2000, notification_tunnel_mtu);
}

TEST_F(MtuTrackerTest, TestCreateWithInitialMtuIPv6) {
  absl::Notification uplink_mtu_updated;
  absl::Notification downlink_mtu_updated;
  int notification_tunnel_mtu;
  EXPECT_CALL(notification_, UplinkMtuUpdated(2000, _))
      .WillOnce([&uplink_mtu_updated, &notification_tunnel_mtu](
                    int /*uplink_mtu*/, int tunnel_mtu) {
        notification_tunnel_mtu = tunnel_mtu;
        uplink_mtu_updated.Notify();
      });
  EXPECT_CALL(notification_, DownlinkMtuUpdated(2000))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv6, 2000, &notification_, &looper_);

  uplink_mtu_updated.WaitForNotification();
  downlink_mtu_updated.WaitForNotification();

  // Verify that tunnel MTU is accounting for overhead
  EXPECT_GT(2000, notification_tunnel_mtu);
}

TEST_F(MtuTrackerTest, TestSetLowerUplinkMtu) {
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, _));

  absl::Notification uplink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1499, _))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, 1500, &notification_, &looper_);
  mtu_tracker.UpdateUplinkMtu(1499);

  uplink_mtu_updated.WaitForNotification();
}

TEST_F(MtuTrackerTest, TestSetHigherUplinkMtu) {
  EXPECT_CALL(notification_, UplinkMtuUpdated(1501, _)).Times(0);
  EXPECT_CALL(notification_, UplinkMtuUpdated(1500, _));

  absl::Notification uplink_mtu_updated;
  EXPECT_CALL(notification_, UplinkMtuUpdated(1499, _))
      .WillOnce([&uplink_mtu_updated] { uplink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, 1500, &notification_, &looper_);
  mtu_tracker.UpdateUplinkMtu(1501);
  mtu_tracker.UpdateUplinkMtu(1499);

  uplink_mtu_updated.WaitForNotification();
}

TEST_F(MtuTrackerTest, TestSetLowerDownlinkMtu) {
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500));

  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1499))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, 1500, &notification_, &looper_);
  mtu_tracker.UpdateDownlinkMtu(1499);

  downlink_mtu_updated.WaitForNotification();
}

TEST_F(MtuTrackerTest, TestSetHigherDownlinkMtu) {
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1500));

  EXPECT_CALL(notification_, DownlinkMtuUpdated(1501)).Times(0);

  absl::Notification downlink_mtu_updated;
  EXPECT_CALL(notification_, DownlinkMtuUpdated(1499))
      .WillOnce([&downlink_mtu_updated] { downlink_mtu_updated.Notify(); });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, 1500, &notification_, &looper_);
  mtu_tracker.UpdateDownlinkMtu(1501);
  mtu_tracker.UpdateDownlinkMtu(1499);

  downlink_mtu_updated.WaitForNotification();
}

TEST_F(MtuTrackerTest, TestGetTunnelMtu) {
  absl::Notification uplink_mtu_updated;
  int notification_tunnel_mtu;
  EXPECT_CALL(notification_, UplinkMtuUpdated(_, _))
      .WillOnce([&uplink_mtu_updated, &notification_tunnel_mtu](
                    int /*uplink_mtu*/, int tunnel_mtu) {
        notification_tunnel_mtu = tunnel_mtu;
        uplink_mtu_updated.Notify();
      });

  MtuTracker mtu_tracker =
      MtuTracker(IPProtocol::kIPv4, &notification_, &looper_);

  uplink_mtu_updated.WaitForNotification();

  // Verify that tunnel MTU is accounting for overhead
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), notification_tunnel_mtu);
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
