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

#include "privacy/net/krypton/datapath/android_ipsec/mss_mtu_detector.h"

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <memory>
#include <optional>
#include <tuple>
#include <utility>

#include "privacy/net/krypton/datapath/android_ipsec/test_utils.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/notification.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {
const int64_t kTimeoutMs = absl::ToInt64Milliseconds(absl::Minutes(1));
constexpr uint32_t kMssIpv4 = 536;
constexpr uint32_t kMssIpv6 = 1220;
}  // namespace

using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Optional;
using ::testing::status::IsOk;
using ::testing::status::StatusIs;

class MockSyscallInterface : public SyscallInterface {
 public:
  MOCK_METHOD((int), GetSockOpt, (int, int, int, void*, socklen_t*),
              (override));
};

class MssMtuDetectorTest
    : public ::testing::TestWithParam<std::tuple<IPProtocol, IPProtocol>> {
 protected:
  MssMtuDetectorTest()
      : client_sock_(LocalSocketFamily(), kTimeoutMs, SocketMode::kNonBlocking),
        server_sock_(ServerAddressFamily(), kTimeoutMs, SocketMode::kBlocking) {
  }

  void SetUp() override {
    auto mock_syscall = std::make_unique<MockSyscallInterface>();

    int expected_mss = kMssIpv4;
    if (ServerAddressFamily() == IPProtocol::kIPv6) {
      expected_mss = kMssIpv6;
    }

    EXPECT_CALL(*mock_syscall, GetSockOpt(_, _, _, _, _))
        .WillRepeatedly([expected_mss](int sockfd, int level, int optname,
                                       void* optval, socklen_t* optlen) {
          int ret = getsockopt(sockfd, level, optname, optval, optlen);
          if (ret != 0) {
            return ret;
          }
          if (level == IPPROTO_TCP && optname == TCP_MAXSEG) {
            // Override the returned MSS value.
            if (*optlen < sizeof(expected_mss)) {
              memcpy(optval, &expected_mss, *optlen);
            } else {
              memcpy(optval, &expected_mss, sizeof(expected_mss));
              *optlen = sizeof(expected_mss);
            }
          }
          return ret;
        });

    mss_mtu_detector_ = std::make_unique<MssMtuDetector>(
        client_sock_.DetachFd(), server_sock_.endpoint(), &events_helper_,
        std::move(mock_syscall));
  }

  int fd() const { return mss_mtu_detector_->fd_; }

  IPProtocol LocalSocketFamily() const { return std::get<0>(GetParam()); }

  IPProtocol ServerAddressFamily() const { return std::get<1>(GetParam()); }

  uint32_t Mtu() const {
    if (ServerAddressFamily() == IPProtocol::kIPv6) {
      return kMssIpv6 + sizeof(tcphdr) + sizeof(ip6_hdr);
    }
    return kMssIpv4 + sizeof(tcphdr) + sizeof(iphdr);
  }

  bool ConnectStarted() const {
    return mss_mtu_detector_->state_ == MssMtuDetector::State::kConnectStarted;
  }

  bool Connected() const {
    return mss_mtu_detector_->state_ == MssMtuDetector::State::kConnected;
  }

  bool Error() const {
    return mss_mtu_detector_->state_ == MssMtuDetector::State::kError;
  }

  LocalTcpSocket client_sock_;
  LocalTcpSocket server_sock_;
  EventsHelper events_helper_;
  std::unique_ptr<MssMtuDetector> mss_mtu_detector_;
};

INSTANTIATE_TEST_SUITE_P(
    IsIpv6, MssMtuDetectorTest,
    ::testing::Values(std::tuple<IPProtocol, IPProtocol>(IPProtocol::kIPv4,
                                                         IPProtocol::kIPv4),
                      std::tuple<IPProtocol, IPProtocol>(IPProtocol::kIPv6,
                                                         IPProtocol::kIPv6)));

TEST_P(MssMtuDetectorTest, fd) { EXPECT_THAT(fd(), Eq(client_sock_.fd())); }

TEST_P(MssMtuDetectorTest, StateAfterStart) {
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  EXPECT_THAT(ConnectStarted(), IsTrue());
}

TEST_P(MssMtuDetectorTest, EmptyMtusIfNotAvailable) {
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  EXPECT_THAT(mss_mtu_detector_->uplink_mss_mtu(), Eq(std::nullopt));
  EXPECT_THAT(mss_mtu_detector_->downlink_mss_mtu(), Eq(std::nullopt));
}

TEST_P(MssMtuDetectorTest, UplinkMtuAfterConnected) {
  absl::Notification server_up;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /* send_data = */ false,
                              &server_up);
  server_up.WaitForNotification();
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  EventsHelper::Event event;
  int num_events = 0;
  absl::Status status = events_helper_.Wait(
      &event, /* max_events = */ 1, /* timeout_ms = */ 500, &num_events);
  ASSERT_THAT(status, IsOk()) << "events_helper_.Wait failed: " << status;
  ASSERT_THAT(num_events, Eq(1));
  ASSERT_THAT(EventsHelper::FileFromEvent(event), Eq(fd()));
  EXPECT_THAT(EventsHelper::FileCanWrite(event), IsTrue());
  auto update_info_or = mss_mtu_detector_->HandleEvent(event);
  EXPECT_THAT(update_info_or.status(), IsOk());
  EXPECT_THAT(update_info_or.value().uplink,
              MssMtuDetector::UpdateResult::kUpdated);
  EXPECT_THAT(update_info_or.value().downlink,
              MssMtuDetector::UpdateResult::kNotUpdated);

  EXPECT_THAT(Error(), IsFalse());
  EXPECT_THAT(Connected(), IsTrue());
  EXPECT_THAT(mss_mtu_detector_->uplink_mss_mtu(), Optional(Mtu()));
}

TEST_P(MssMtuDetectorTest, DownlinkMtuAfterReceived) {
  absl::Notification server_up;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /* send_data = */ true,
                              &server_up);
  server_up.WaitForNotification();
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  constexpr int kMaxEvents = 4;
  EventsHelper::Event events[kMaxEvents];
  int num_events = 0;
  MssMtuDetector::UpdateResult downlink_mss_mtu_update_result =
      MssMtuDetector::UpdateResult::kNotUpdated;
  while (downlink_mss_mtu_update_result !=
         MssMtuDetector::UpdateResult::kUpdated) {
    absl::Status status = events_helper_.Wait(
        events, kMaxEvents, /* timeout_ms = */ 500, &num_events);
    ASSERT_THAT(status, IsOk()) << "events_helper_.Wait failed: " << status;
    for (int i = 0; i < num_events; i++) {
      ASSERT_THAT(EventsHelper::FileFromEvent(events[i]), Eq(fd()));
      auto update_info_or = mss_mtu_detector_->HandleEvent(events[i]);
      EXPECT_THAT(update_info_or.status(), IsOk());
      EXPECT_THAT(Error(), IsFalse());
      downlink_mss_mtu_update_result = update_info_or.value().downlink;
    }
  }

  EXPECT_THAT(mss_mtu_detector_->downlink_mss_mtu(), Optional(Mtu()));
}

TEST_P(MssMtuDetectorTest, NoServer) {
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  EventsHelper::Event event;
  int num_events = 0;
  absl::Status status = events_helper_.Wait(
      &event, /* max_events = */ 1, /* timeout_ms = */ 500, &num_events);
  ASSERT_THAT(status, IsOk()) << "events_helper_.Wait failed: " << status;
  ASSERT_THAT(num_events, Eq(1));
  ASSERT_THAT(EventsHelper::FileFromEvent(event), Eq(fd()));

  EXPECT_THAT(EventsHelper::FileHasError(event), IsTrue());
  EXPECT_THAT(mss_mtu_detector_->HandleEvent(event),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("Error event")));

  EXPECT_THAT(Error(), IsTrue());
  EXPECT_THAT(Connected(), IsFalse());
  EXPECT_THAT(mss_mtu_detector_->uplink_mss_mtu(), Eq(std::nullopt));
  EXPECT_THAT(mss_mtu_detector_->downlink_mss_mtu(), Eq(std::nullopt));
}

TEST_P(MssMtuDetectorTest, DownlinkMtuNotReceived) {
  absl::Notification server_up;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /* send_data = */ false,
                              &server_up);
  server_up.WaitForNotification();
  ASSERT_THAT(mss_mtu_detector_->Start(), IsOk());

  EventsHelper::Event event;
  int num_events = 0;
  absl::Status status;
  absl::StatusOr<MssMtuDetector::MssMtuUpdateInfo> update_info_or;
  while (true) {
    status = events_helper_.Wait(&event, /* max_events = */ 1,
                                 /* timeout_ms = */ 500, &num_events);
    ASSERT_THAT(status, IsOk()) << "events_helper_.Wait failed: " << status;
    if (num_events <= 0) {
      continue;
    }
    ASSERT_THAT(EventsHelper::FileFromEvent(event), Eq(fd()));
    update_info_or = mss_mtu_detector_->HandleEvent(event);
    if (!update_info_or.status().ok()) {
      break;
    }
    EXPECT_THAT(update_info_or.value().downlink,
                Eq(MssMtuDetector::UpdateResult::kNotUpdated));
  }

  EXPECT_THAT(update_info_or.status(),
              StatusIs(util::error::INTERNAL,
                       HasSubstr("recv returns 0. Server has closed "
                                 "the connection unexpectedly")));
  EXPECT_THAT(Error(), IsTrue());
  EXPECT_THAT(mss_mtu_detector_->uplink_mss_mtu(), Optional(Mtu()));
  EXPECT_THAT(mss_mtu_detector_->downlink_mss_mtu(), Eq(std::nullopt));
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
