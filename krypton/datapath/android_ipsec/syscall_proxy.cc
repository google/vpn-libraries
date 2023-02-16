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

#include <sys/socket.h>

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

int SyscallProxy::GetSockOpt(int sockfd, int level, int optname, void* optval,
                             socklen_t* optlen) {
  return getsockopt(sockfd, level, optname, optval, optlen);
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
