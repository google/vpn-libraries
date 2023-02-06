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

#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

TEST(MtuTrackerTest, TestCreateWithDefault) {
  MtuTracker mtu_tracker = MtuTracker();
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1395);
}

TEST(MtuTrackerTest, TestCreateWithCustomMtu) {
  MtuTracker mtu_tracker = MtuTracker(2000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 2000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1895);
}

TEST(MtuTrackerTest, TestSetLowerMtu) {
  MtuTracker mtu_tracker = MtuTracker();
  mtu_tracker.UpdateMtu(1000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1000);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 895);
}

TEST(MtuTrackerTest, TestSetHigherMtu) {
  MtuTracker mtu_tracker = MtuTracker();
  mtu_tracker.UpdateMtu(2000);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1395);
}

TEST(MtuTrackerTest, TestChangeIpProtocol) {
  MtuTracker mtu_tracker = MtuTracker();
  mtu_tracker.UpdateDestIpProtocol(IPProtocol::kIPv6);
  EXPECT_EQ(mtu_tracker.GetPathMtu(), 1500);
  EXPECT_EQ(mtu_tracker.GetTunnelMtu(), 1423);
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
