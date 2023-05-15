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

#include "privacy/net/krypton/datapath/android_ipsec/syscall_proxy.h"

#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

TEST(SyscallProxyTest, GetSockOpt) {
  SyscallProxy proxy;
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  int optval = 0;
  socklen_t optlen = sizeof(optval);
  EXPECT_EQ(proxy.GetSockOpt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen), 0);
  EXPECT_EQ(optlen, sizeof(optval));
  EXPECT_EQ(optval, SOCK_STREAM);
  close(fd);
}

TEST(SyscallProxyTest, GetSockOptInvalidFd) {
  SyscallProxy proxy;
  int optval = 0;
  socklen_t optlen = sizeof(optval);
  EXPECT_EQ(proxy.GetSockOpt(-1, SOL_SOCKET, SO_TYPE, &optval, &optlen), -1);
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
