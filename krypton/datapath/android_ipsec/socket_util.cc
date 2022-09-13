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
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

namespace {

// We don't use net_base::SetSocketNonBlocking because //net/base/sockoptions.cc
// doesn't compile on android.
::absl::Status SetSocketBlockingStatus(int fd, bool is_blocking) {
  int old_flags = fcntl(fd, F_GETFL, 0);
  if (old_flags < 0) {
    return ::absl::InternalError(absl::StrCat(
        "SetBlockingStatus of fd: ", fd, "fcntl F_GETFL: ", strerror(errno)));
  }

  if (is_blocking) {
    old_flags &= ~O_NONBLOCK;
  } else {
    old_flags |= O_NONBLOCK;
  }

  if (fcntl(fd, F_SETFL, old_flags) != 0) {
    return ::absl::InternalError(absl::StrCat(
        "SetBlockingStatus of fd ", fd, ": fcntl F_SETFL: ", strerror(errno)));
  }

  return ::absl::OkStatus();
}

}  // namespace

::absl::Status SetSocketBlocking(int fd) {
  return SetSocketBlockingStatus(fd, /*is_blocking= */ true);
}

absl::Status FdError(absl::StatusCode status_code, int fd) {
  int error = 0;
  socklen_t errlen = sizeof(error);

  // Clear the error that is reported on the socket.
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<void*>(&error),
                 &errlen) < 0) {
    return absl::Status(
        status_code,
        absl::Substitute("getsockopt(SO_ERROR): $0", strerror(errno)));
  }
  return absl::Status(status_code, strerror(error));
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
