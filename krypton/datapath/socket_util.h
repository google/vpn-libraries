// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_SOCKET_UTIL_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_SOCKET_UTIL_H_

#include <netinet/in.h>

#include <string>

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace datapath {

// Sets the given socket fd in blocking mode.
absl::Status SetSocketBlocking(int fd);

// Sets the given socket fd in non blocking mode.
absl::Status SetSocketNonBlocking(int fd);

// Tells the error of the socket, and a message describing the error. If failed
// to retrieve the socket error, it returns -1 and the msg describes the failure
// of retrieving error.
int FdError(int fd, std::string* msg);
absl::Status FdError(absl::StatusCode status_code, int fd);

// Connects the given file descriptor to the given remote address.
int Connect(int fd, const sockaddr_storage& dest);

}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_SOCKET_UTIL_H_
