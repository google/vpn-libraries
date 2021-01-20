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

#ifndef PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_

#include "privacy/net/krypton/pal/vpn_service_interface.h"

namespace privacy {
namespace krypton {

// A PacketPipe that's backed by a file descriptor.
class FdPacketPipe : public PacketPipe {
 public:
  explicit FdPacketPipe(int fd) : fd_(fd) {}
  ~FdPacketPipe() override {}

  absl::Status WritePacket(Packet /*packet*/) override {
    return absl::UnimplementedError("unimplemented");
  }

  void ReadPacket(void handler(absl::Status status, Packet packet)) override {
    Packet packet;
    handler(absl::UnimplementedError("unimplemented"), packet);
  }

  absl::StatusOr<int> GetFd() const override { return fd_; }

  void Close() override { close(fd_); }

  std::string DebugString() override { return absl::StrCat("FD=", fd_); }

 private:
  int fd_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
