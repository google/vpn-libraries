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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_INTERFACE_H_

#include <sys/socket.h>

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// This interface will act as a proxy for syscalls, making them mockable for
// tests when necessary.
class SyscallInterface {
 public:
  virtual ~SyscallInterface() = default;

  virtual int GetSockOpt(int sockfd, int level, int optname, void* optval,
                         socklen_t* optlen) = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_INTERFACE_H_
