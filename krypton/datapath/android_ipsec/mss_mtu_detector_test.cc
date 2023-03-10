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
using ::testing::HasSubstr;
using ::testing::status::StatusIs;

class MockSyscallInterface : public SyscallInterface {
 public:
  MOCK_METHOD((int), GetSockOpt, (int, int, int, void*, socklen_t*),
              (override));
};

class MockNotification : public MssMtuDetectorInterface::NotificationInterface {
 public:
  MOCK_METHOD(void, MssMtuSuccess, (int, int), (override));
  MOCK_METHOD(void, MssMtuFailure, (absl::Status), (override));
};

class MssMtuDetectorTest
    : public ::testing::TestWithParam<std::tuple<IPProtocol, IPProtocol>> {
 protected:
  MssMtuDetectorTest()
      : client_sock_(LocalSocketFamily(), kTimeoutMs, SocketMode::kNonBlocking),
        server_sock_(ServerAddressFamily(), kTimeoutMs, SocketMode::kBlocking),
        thread_("MSS MTU Detector Test") {}

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
        client_sock_.DetachFd(), server_sock_.endpoint(),
        std::move(mock_syscall), &notification_, &thread_);
  }

  IPProtocol LocalSocketFamily() const { return std::get<0>(GetParam()); }

  IPProtocol ServerAddressFamily() const { return std::get<1>(GetParam()); }

  uint32_t Mtu() const {
    if (ServerAddressFamily() == IPProtocol::kIPv6) {
      return kMssIpv6 + sizeof(tcphdr) + sizeof(ip6_hdr);
    }
    return kMssIpv4 + sizeof(tcphdr) + sizeof(iphdr);
  }

  LocalTcpSocket client_sock_;
  LocalTcpSocket server_sock_;
  MockNotification notification_;
  utils::LooperThread thread_;
  std::unique_ptr<MssMtuDetector> mss_mtu_detector_;
};

INSTANTIATE_TEST_SUITE_P(
    IsIpv6, MssMtuDetectorTest,
    ::testing::Values(std::tuple<IPProtocol, IPProtocol>(IPProtocol::kIPv4,
                                                         IPProtocol::kIPv4),
                      std::tuple<IPProtocol, IPProtocol>(IPProtocol::kIPv6,
                                                         IPProtocol::kIPv6)));

TEST_P(MssMtuDetectorTest, MssDetectionSuccessful) {
  absl::Notification server_up;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /*send_data =*/true,
                              &server_up);
  server_up.WaitForNotification();

  absl::Notification mss_mtu_done;
  EXPECT_CALL(notification_, MssMtuSuccess(_, Mtu()))
      .WillOnce(testing::InvokeWithoutArgs(&mss_mtu_done,
                                           &absl::Notification::Notify));

  mss_mtu_detector_->Start();

  EXPECT_TRUE(mss_mtu_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_P(MssMtuDetectorTest, NoServer) {
  absl::Notification mss_mtu_done;
  EXPECT_CALL(notification_,
              MssMtuFailure(StatusIs(absl::StatusCode::kInternal,
                                     HasSubstr("Connection refused"))))
      .WillOnce(testing::InvokeWithoutArgs(&mss_mtu_done,
                                           &absl::Notification::Notify));

  mss_mtu_detector_->Start();

  EXPECT_TRUE(mss_mtu_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_P(MssMtuDetectorTest, DownlinkMtuNotReceived) {
  absl::Notification server_up;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /*send_data =*/false,
                              &server_up);
  server_up.WaitForNotification();

  absl::Notification mss_mtu_done;
  EXPECT_CALL(
      notification_,
      MssMtuFailure(StatusIs(absl::StatusCode::kInternal,
                             HasSubstr("Server has closed the connection"))))
      .WillOnce(testing::InvokeWithoutArgs(&mss_mtu_done,
                                           &absl::Notification::Notify));

  mss_mtu_detector_->Start();

  EXPECT_TRUE(mss_mtu_done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_P(MssMtuDetectorTest, StopBeforeMssDetectionComplete) {
  absl::Notification server_up;
  absl::Notification start_send_data;
  LocalTcpMssMtuServer server(&server_sock_, Mtu(), /*send_data =*/false,
                              &server_up, &start_send_data);
  server_up.WaitForNotification();

  absl::Notification mss_mtu_done;
  EXPECT_CALL(notification_,
              MssMtuFailure(StatusIs(absl::StatusCode::kAborted)))
      .WillOnce(testing::InvokeWithoutArgs(&mss_mtu_done,
                                           &absl::Notification::Notify));

  mss_mtu_detector_->Start();

  mss_mtu_detector_->Stop();

  EXPECT_TRUE(mss_mtu_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  start_send_data.Notify();
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
