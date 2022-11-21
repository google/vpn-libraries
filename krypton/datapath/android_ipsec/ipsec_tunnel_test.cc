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

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_tunnel.h"

#include <sys/socket.h>

#include <memory>
#include <utility>
#include <vector>

#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

class IpSecTunnelTest : public ::testing::Test {
 public:
  void SetUp() override {}
  void TearDown() override {}

 protected:
  static absl::StatusOr<std::pair<int, int>> CreateSocketPair() {
    int sock_fds[2];
    if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, sock_fds) < 0) {
      return absl::InternalError("unable to create pipe");
    }
    return std::pair<int, int>(sock_fds[0], sock_fds[1]);
  }
};

TEST_F(IpSecTunnelTest, CreateAndClose) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, CloseAfterClose) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  ASSERT_OK(tunnel->Close());

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, CreateAndStop) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  absl::Notification notification;

  krypton::utils::LooperThread thread("CreateAndStop Thread");
  thread.Post([&tunnel, &notification]() {
    ASSERT_OK_AND_ASSIGN(auto packets, tunnel->ReadPackets());
    ASSERT_TRUE(packets.empty());
    notification.Notify();
  });

  ASSERT_OK(tunnel->CancelReadPackets());

  ASSERT_TRUE(
      notification.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, WriteAfterClose) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  ASSERT_OK(tunnel->Close());

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_THAT(tunnel->WritePackets(std::move(packets)),
              ::testing::status::StatusIs(absl::StatusCode::kInternal));

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, ReadAfterClose) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  ASSERT_OK(tunnel->Close());

  ASSERT_THAT(tunnel->ReadPackets(),
              ::testing::status::StatusIs(absl::StatusCode::kInternal));

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, NormalWrite) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  // Send a packet through.
  std::vector<Packet> send_packets;
  send_packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_OK(tunnel->WritePackets(std::move(send_packets)));

  // Verify the other end received the packet.
  char msg[10];
  int nread = read(sock_fds.second, msg, 10);
  EXPECT_EQ("foo", std::string(msg, nread));

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, NormalRead) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  // Send a packet to the tunnel.
  write(sock_fds.second, "foo", 3);

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, ReadAfterShutdown) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  shutdown(sock_fds.first, SHUT_RDWR);

  ASSERT_THAT(tunnel->ReadPackets(),
              testing::status::StatusIs(absl::StatusCode::kAborted));

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, SetKeepalive) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  EXPECT_FALSE(tunnel->IsKeepaliveEnabled());

  tunnel->SetKeepaliveInterval(absl::Milliseconds(1));

  EXPECT_TRUE(tunnel->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel->GetKeepaliveInterval(), absl::Milliseconds(1));

  tunnel->SetKeepaliveInterval(absl::ZeroDuration());

  EXPECT_FALSE(tunnel->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel->GetKeepaliveInterval(), absl::ZeroDuration());

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

TEST_F(IpSecTunnelTest, ReadKeepalive) {
  ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());

  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(sock_fds.first));

  tunnel->SetKeepaliveInterval(absl::Milliseconds(1));

  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "\xFF");

  ASSERT_OK(tunnel->Close());

  close(sock_fds.second);
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
