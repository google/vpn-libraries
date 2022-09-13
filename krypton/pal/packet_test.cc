// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/pal/packet.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace {

class PacketTest : public ::testing::Test {};

TEST_F(PacketTest, TestUnownedData) {
  const char *data = "foo";
  {
    Packet packet(data, 3, IPProtocol::kIPv4, []() {});
    EXPECT_EQ("foo", packet.data().data());
    EXPECT_EQ(3, packet.data().length());
    EXPECT_EQ(IPProtocol::kIPv4, packet.protocol());
  }
  // Data is still valid even though the Packet is gone.
  EXPECT_EQ("foo", data);
}

TEST_F(PacketTest, TestCleanup) {
  bool called = false;
  {
    Packet packet("foo", 3, IPProtocol::kIPv4, [&called] { called = true; });
  }
  ASSERT_TRUE(called);
}

TEST_F(PacketTest, TestMove) {
  Packet original("foo", 3, IPProtocol::kIPv4, []() {});
  Packet packet = std::move(original);

  EXPECT_EQ("foo", packet.data().data());
  EXPECT_EQ(3, packet.data().length());
  EXPECT_EQ(IPProtocol::kIPv4, packet.protocol());
}

TEST_F(PacketTest, TestMoveCleanup) {
  std::atomic_int called = 0;
  {
    Packet packet("foo", 3, IPProtocol::kIPv4, [&called] { called++; });
    {
      // Moving the packet should reset the cleanup, so it only gets called
      // once.
      Packet copy = std::move(packet);
    }
    // Now that the copy is destroyed, the cleanup should've been called.
    ASSERT_EQ(1, called);
  }
  // Destroying the old one shouldn't do anything.
  ASSERT_EQ(1, called);
}

TEST_F(PacketTest, TestMallocData) {
  char *data = static_cast<char *>(malloc(3));
  memcpy(data, "foo", 3);
  // If we don't free the packet here, the heapchecker will fail the test.
  Packet packet(data, 3, IPProtocol::kIPv4, [data]() { free(data); });
}

TEST_F(PacketTest, TestNewData) {
  char *data = new char[3];
  memcpy(data, "foo", 3);
  // If we don't free the packet here, the heapchecker will fail the test.
  Packet packet(data, 3, IPProtocol::kIPv4, [data]() { delete[] data; });
}

TEST_F(PacketTest, CleansUpOldDataOnAssignment) {
  bool cleaned_up = false;
  Packet old_packet(nullptr, 0, IPProtocol::kUnknown,
                    [&cleaned_up]() { cleaned_up = true; });
  old_packet = Packet();
  ASSERT_TRUE(cleaned_up);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
