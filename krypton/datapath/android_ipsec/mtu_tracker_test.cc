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

#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/synchronization/notification.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::_;

class MockNotification : public MtuTrackerInterface::NotificationInterface {
 public:
  MOCK_METHOD(void, MtuUpdated, (int, int), (override));
};

TEST(MtuTrackerTest, TestCreateWithDefaultIpv4) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1395);
}

TEST(MtuTrackerTest, TestCreateWithDefaultIPv6) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv6);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1423);
}

TEST(MtuTrackerTest, TestCreateWithCustomMtu) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4, 2000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 2000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1895);
}

TEST(MtuTrackerTest, TestSetLowerMtu) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.UpdateMtu(1000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 895);
}

TEST(MtuTrackerTest, TestSetHigherMtu) {
  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.UpdateMtu(2000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1395);
}

TEST(MtuTrackerTest, TestUpdateMtuWithNullNotificationThread) {
  MockNotification notification;

  EXPECT_CALL(notification, MtuUpdated(_, _)).Times(0);

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification, nullptr);
  mtu_tracker.UpdateMtu(1000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 895);
}

TEST(MtuTrackerTest, TestUpdateMtuWithNotification) {
  utils::LooperThread looper("MtuTrackerTest Thread");
  MockNotification notification;

  absl::Notification mtu_update_done;
  EXPECT_CALL(notification, MtuUpdated(1000, 895))
      .WillOnce([&mtu_update_done]() { mtu_update_done.Notify(); });

  MtuTracker mtu_tracker = MtuTracker(IPProtocol::kIPv4);
  mtu_tracker.RegisterNotificationHandler(&notification, &looper);
  mtu_tracker.UpdateMtu(1000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 895);

  EXPECT_TRUE(mtu_update_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
