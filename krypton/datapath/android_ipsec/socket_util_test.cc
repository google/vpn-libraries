// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

using ::testing::Ge;

TEST(SocketUtilTest, SetSocketBlocking) {
  EventFd fd_helper_;
  int fd = fd_helper_.fd();

  CHECK_OK(SetSocketBlocking(fd));

  int flags = fcntl(fd, F_GETFL, 0);
  ASSERT_FALSE(flags & O_NONBLOCK);
}

TEST(SocketUtilTest, SetSocketNonBlocking) {
  EventFd fd_helper_;
  int fd = fd_helper_.fd();

  int flags = fcntl(fd, F_GETFL, 0);
  ASSERT_TRUE(flags & O_NONBLOCK);
}

TEST(SocketUtilTest, CreateEventFd) {
  EventFd fd_helper_;
  CHECK_NE(fd_helper_.fd(), -1);
}

TEST(SocketUtilTest, NotifyEventFd) {
  EventFd fd_helper_;
  int fd = fd_helper_.fd();

  CHECK_OK(fd_helper_.Notify(1));

  uint64_t op = 10;
  int ret = read(fd, &op, sizeof(op));
  ASSERT_NE(ret, -1);
  ASSERT_EQ(op, 1);
}

TEST(SocketUtilTest, FdErrorGood) {
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  ASSERT_THAT(fd, Ge(0)) << absl::Substitute("socket: $0", strerror(errno));

  std::string msg;
  EXPECT_EQ(FdError(fd, &msg), 0);
  EXPECT_EQ(msg, "Success");

  close(fd);
}

TEST(SocketUtilTest, FdErrorInvalidFd) {
  std::string msg;
  EXPECT_EQ(FdError(-1, &msg), -1);
  EXPECT_EQ(msg, "getsockopt(SO_ERROR): Bad file descriptor");
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
