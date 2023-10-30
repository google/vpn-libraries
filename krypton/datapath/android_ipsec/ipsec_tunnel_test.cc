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

#include <fcntl.h>
#include <sys/socket.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/fd_util.h"
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

using ::testing::DoAll;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::status::StatusIs;

class IpSecTunnelTest : public ::testing::Test {
 public:
  IpSecTunnelTest()
      : tun_fd1_(-1), sock_fd1_(-1), timer_manager_(&mock_timer_interface_) {}

  void SetUp() override {
    ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
    tun_fd1_ = tun_fd2;
    sock_fd1_ = sock_fd2;

    ASSERT_OK_AND_ASSIGN(tunnel_, CreateTunnel());
  }

  void TearDown() override { CloseSocket(); }

 protected:
  static absl::StatusOr<std::pair<int, int>> CreateSocketPair() {
    int sock_fds[2];
    if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, sock_fds) < 0) {
      return absl::InternalError("unable to create pipe");
    }
    return std::pair<int, int>(sock_fds[0], sock_fds[1]);
  }

  absl::StatusOr<std::unique_ptr<IpSecTunnel>> CreateTunnel() {
    return IpSecTunnel::Create(tun_fd1_, &timer_manager_);
  }

  void CloseSocket() {
    if (sock_fd1_ != -1) {
      close(sock_fd1_);
      sock_fd1_ = -1;
    }
  }

  int tun_fd1_;
  int sock_fd1_;
  MockTimerInterface mock_timer_interface_;
  TimerManager timer_manager_;

  std::unique_ptr<IpSecTunnel> tunnel_;
};

TEST_F(IpSecTunnelTest, CreateTunnel) { tunnel_->Close(); }

TEST_F(IpSecTunnelTest, CreateTunnelWithBadFd) {
  ASSERT_THAT(IpSecTunnel::Create(-1, &timer_manager_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(IpSecTunnelTest, NormalWrite) {
  // Send a packet through.
  std::vector<Packet> send_packets;
  send_packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_OK(tunnel_->WritePackets(std::move(send_packets)));

  // Verify the other end received the packet.
  char msg[10];
  int nread = read(sock_fd1_, msg, 10);
  EXPECT_EQ("foo", std::string(msg, nread));
}

TEST_F(IpSecTunnelTest, WriteAfterClose) {
  ASSERT_OK(CloseFd(tun_fd1_));
  tun_fd1_ = -1;

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});
  ASSERT_THAT(tunnel_->WritePackets(std::move(packets)),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(IpSecTunnelTest, NormalRead) {
  // Send a packet to the tunnel_.
  write(sock_fd1_, "foo", 3);

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ReadAfterCancelReadPackets) {
  tunnel_->CancelReadPackets();

  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_THAT(recv_packets, IsEmpty());
}

TEST_F(IpSecTunnelTest, ResetClearsCancelReadPackets) {
  tunnel_->CancelReadPackets();
  write(sock_fd1_, "foo", 3);

  ASSERT_OK(tunnel_->Reset());

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ResetClearsMultipleCancelReadPackets) {
  tunnel_->CancelReadPackets();
  tunnel_->CancelReadPackets();
  write(sock_fd1_, "foo", 3);

  ASSERT_OK(tunnel_->Reset());

  // Verify the packet was received
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
}

TEST_F(IpSecTunnelTest, ReadAfterShutdown) {
  shutdown(tun_fd1_, SHUT_RDWR);

  ASSERT_THAT(tunnel_->ReadPackets(), StatusIs(absl::StatusCode::kAborted));
}

TEST_F(IpSecTunnelTest, SetKeepalive) {
  EXPECT_FALSE(tunnel_->IsKeepaliveEnabled());

  tunnel_->SetKeepaliveInterval(absl::Milliseconds(1));

  EXPECT_TRUE(tunnel_->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel_->GetKeepaliveInterval(), absl::Milliseconds(1));

  tunnel_->SetKeepaliveInterval(absl::ZeroDuration());

  EXPECT_FALSE(tunnel_->IsKeepaliveEnabled());
  EXPECT_EQ(tunnel_->GetKeepaliveInterval(), absl::ZeroDuration());
}

TEST_F(IpSecTunnelTest, ReadKeepalive) {
  tunnel_->SetKeepaliveInterval(absl::Milliseconds(1));

  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "\xFF");
}

TEST_F(IpSecTunnelTest, CloseClosesPrimaryFd) {
  EXPECT_NE(fcntl(tun_fd1_, F_GETFD), -1);

  tunnel_->Close();

  EXPECT_EQ(fcntl(tun_fd1_, F_GETFD), -1);
}

TEST_F(IpSecTunnelTest, CloseClosesAllFds) {
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  EXPECT_NE(fcntl(tun_fd1_, F_GETFD), -1);
  EXPECT_NE(fcntl(tun_fd2, F_GETFD), -1);

  tunnel_->Close();

  EXPECT_EQ(fcntl(tun_fd1_, F_GETFD), -1);
  EXPECT_EQ(fcntl(tun_fd2, F_GETFD), -1);
}

TEST_F(IpSecTunnelTest, WritesToNewDestinationAfterAdoptFd) {
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  std::vector<Packet> send_packets;
  send_packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});

  ASSERT_OK(tunnel_->WritePackets(std::move(send_packets)));

  // Verify the new destination receives the packet
  char msg[10];
  int nread = read(sock_fd2, msg, 10);
  EXPECT_EQ("foo", std::string(msg, nread));
  EXPECT_OK(CloseFd(sock_fd2));
}

TEST_F(IpSecTunnelTest, ReadsFromAllFdsAfterAdoptFd) {
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));

  // Send a packet to the original socket and verify it is received.
  write(sock_fd1_, "foo", 3);
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");

  // Send a packet to the new tunnel_ and verify it is received.
  write(sock_fd2, "bar", 3);
  ASSERT_OK_AND_ASSIGN(recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "bar");

  EXPECT_OK(CloseFd(sock_fd2));
}

TEST_F(IpSecTunnelTest, FlushFdTimerIgnoresFdWithData) {
  int timer_id;
  EXPECT_CALL(mock_timer_interface_, StartTimer)
      .WillOnce(DoAll(SaveArg<0>(&timer_id), Return(absl::OkStatus())))
      .WillOnce(Return(absl::OkStatus()));
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  write(sock_fd1_, "foo", 3);

  mock_timer_interface_.TimerExpiry(timer_id);

  EXPECT_NE(fcntl(tun_fd1_, F_GETFD), -1);
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());
  ASSERT_EQ(recv_packets.size(), 1);
  EXPECT_EQ(recv_packets[0].data(), "foo");
  EXPECT_OK(CloseFd(sock_fd2));
}

TEST_F(IpSecTunnelTest, FlushFdTimerClosesFdWithoutData) {
  int timer_id;
  EXPECT_CALL(mock_timer_interface_, StartTimer)
      .WillOnce(DoAll(SaveArg<0>(&timer_id), Return(absl::OkStatus())));
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  write(sock_fd1_, "foo", 3);
  ASSERT_OK_AND_ASSIGN(auto recv_packets, tunnel_->ReadPackets());

  mock_timer_interface_.TimerExpiry(timer_id);

  EXPECT_EQ(fcntl(tun_fd1_, F_GETFD), -1);
  EXPECT_OK(CloseFd(sock_fd2));
}

TEST_F(IpSecTunnelTest, FlushFdTimerCancelsOldTimers) {
  int timer_id1;
  int timer_id2;
  EXPECT_CALL(mock_timer_interface_, StartTimer)
      .WillOnce(DoAll(SaveArg<0>(&timer_id1), Return(absl::OkStatus())))
      .WillOnce(DoAll(SaveArg<0>(&timer_id2), Return(absl::OkStatus())));
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK_AND_ASSIGN((auto [tun_fd3, sock_fd3]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  EXPECT_CALL(mock_timer_interface_, CancelTimer(timer_id1));

  ASSERT_OK(tunnel_->AdoptFd(tun_fd3));

  EXPECT_CALL(mock_timer_interface_, CancelTimer(timer_id2));
  EXPECT_OK(CloseFd(sock_fd2));
  EXPECT_OK(CloseFd(sock_fd3));
}

TEST_F(IpSecTunnelTest, FlushFdTimerFailsToStartAndClosesFds) {
  EXPECT_CALL(mock_timer_interface_, StartTimer)
      .WillOnce(Return(absl::InternalError("Failure")));
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());

  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));

  EXPECT_EQ(fcntl(tun_fd1_, F_GETFD), -1);
  EXPECT_OK(CloseFd(sock_fd2));
}

TEST_F(IpSecTunnelTest, CancelledFlushFdTimerIsNotHandled) {
  int timer_id1;
  int timer_id2;
  EXPECT_CALL(mock_timer_interface_, StartTimer)
      .WillOnce(DoAll(SaveArg<0>(&timer_id1), Return(absl::OkStatus())))
      .WillOnce(DoAll(SaveArg<0>(&timer_id2), Return(absl::OkStatus())));
  ASSERT_OK_AND_ASSIGN((auto [tun_fd2, sock_fd2]), CreateSocketPair());
  ASSERT_OK_AND_ASSIGN((auto [tun_fd3, sock_fd3]), CreateSocketPair());
  ASSERT_OK(tunnel_->AdoptFd(tun_fd2));
  absl::Notification first_timer_expired;
  EXPECT_CALL(mock_timer_interface_, CancelTimer(timer_id1))
      .WillOnce([&first_timer_expired] { first_timer_expired.Notify(); });

  ASSERT_OK(tunnel_->AdoptFd(tun_fd3));
  first_timer_expired.WaitForNotification();
  mock_timer_interface_.TimerExpiry(timer_id1);

  EXPECT_NE(fcntl(tun_fd1_, F_GETFD), -1);
  EXPECT_NE(fcntl(tun_fd2, F_GETFD), -1);
  EXPECT_NE(fcntl(tun_fd3, F_GETFD), -1);
  EXPECT_CALL(mock_timer_interface_, CancelTimer(timer_id2));
  EXPECT_OK(CloseFd(sock_fd2));
  EXPECT_OK(CloseFd(sock_fd3));
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
