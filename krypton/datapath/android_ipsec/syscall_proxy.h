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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_PROXY_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_PROXY_H_

#include <sys/socket.h>

#include "privacy/net/krypton/datapath/android_ipsec/syscall_interface.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class SyscallProxy : public SyscallInterface {
 public:
  int GetSockOpt(int sockfd, int level, int optname, void* optval,
                 socklen_t* optlen) override;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SYSCALL_PROXY_H_
