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
#include <string>
#include <utility>
#include <vector>

#include "privacy/net/krypton/pal/packet.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::IsEmpty;
using ::testing::status::StatusIs;

class IpSecTunnelTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(auto sock_fds, CreateSocketPair());
    tun_fd_ = sock_fds.first;
    sock_fd_ = sock_fds.second;
  }
  void TearDown() override {
    CloseTunnel();
    CloseSocket();
  }

 protected:
  static absl::StatusOr<std::pair<int, int>> CreateSocketPair() {
    int sock_fds[2];
    if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, sock_fds) < 0) {
      return absl::InternalError("unable to create pipe");
    }
    return std::pair<int, int>(sock_fds[0], sock_fds[1]);
  }

  void CloseTunnel() {
    if (tun_fd_ != -1) {
      close(tun_fd_);
      tun_fd_ = -1;
    }
  }

  void CloseSocket() {
    if (sock_fd_ != -1) {
      close(sock_fd_);
      sock_fd_ = -1;
    }
  }

  int tun_fd_;
  int sock_fd_;
};

TEST_F(IpSecTunnelTest, CreateTunnel) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));
}

TEST_F(IpSecTunnelTest, CreateTunnelWithBadFd) {
  ASSERT_THAT(IpSecTunnel::Create(-1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(IpSecTunnelTest, NormalWrite) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  // Send a packet through.
  std::vector<Packet> send_packets;
  send_packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_OK(tunnel->WritePackets(std::move(send_packets)));

  // Verify the other end received the packet.
  char msg[10];
  int nread = read(sock_fd_, msg, 10);
  EXPECT_EQ("foo", std::string(msg, nread));
}

TEST_F(IpSecTunnelTest, WriteAfterClose) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  CloseTunnel();

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_THAT(tunnel->WritePackets(std::move(packets)),
              ::testing::status::StatusIs(absl::StatusCode::kInternal));
}

TEST_F(IpSecTunnelTest, NormalRead) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  // Send a packet to the tunnel.
  write(sock_fd_, "foo", 3);

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ReadAfterCancelReadPackets) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  tunnel->CancelReadPackets();

  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_THAT(recv_packets, IsEmpty());
}

TEST_F(IpSecTunnelTest, ResetClearsCancelReadPackets) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));
  tunnel->CancelReadPackets();
  write(sock_fd_, "foo", 3);

  ASSERT_OK(tunnel->Reset());

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ResetClearsMultipleCancelReadPackets) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));
  tunnel->CancelReadPackets();
  tunnel->CancelReadPackets();
  write(sock_fd_, "foo", 3);

  ASSERT_OK(tunnel->Reset());

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ReadAfterShutdown) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  shutdown(tun_fd_, SHUT_RDWR);

  ASSERT_THAT(tunnel->ReadPackets(),
              testing::status::StatusIs(absl::StatusCode::kAborted));
}

TEST_F(IpSecTunnelTest, SetKeepalive) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  EXPECT_FALSE(tunnel->IsKeepaliveEnabled());

  tunnel->SetKeepaliveInterval(absl::Milliseconds(1));

  EXPECT_TRUE(tunnel->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel->GetKeepaliveInterval(), absl::Milliseconds(1));

  tunnel->SetKeepaliveInterval(absl::ZeroDuration());

  EXPECT_FALSE(tunnel->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel->GetKeepaliveInterval(), absl::ZeroDuration());
}

TEST_F(IpSecTunnelTest, ReadKeepalive) {
  ASSERT_OK_AND_ASSIGN(auto tunnel, IpSecTunnel::Create(tun_fd_));

  tunnel->SetKeepaliveInterval(absl::Milliseconds(1));

  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "\xFF");
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
