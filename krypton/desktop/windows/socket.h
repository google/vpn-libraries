// Copyright 2022 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SOCKET_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SOCKET_H_

#include <Windows.h>
#include <winsock2.h>

#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/socket_interface.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

// Wrapper class for Windows sockets. Socket should be managed by a unique_ptr.
class Socket : public SocketInterface {
 public:
  explicit Socket(SOCKET s) : socket_(s) {}
  ~Socket() override {
    LOG(INFO) << "Destroying Socket";
    closesocket(socket_);
  }

  // Disallow copy and move, so that we don't close a copy of an active socket.
  Socket(const Socket&) = delete;
  Socket(Socket&&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket& operator=(Socket&&) = delete;

  // Add dereference operator for consistency.
  SOCKET operator*() const { return socket_; }

  SOCKET get() const { return socket_; }

  absl::Status Close() override;

  absl::StatusOr<std::vector<Packet>> ReadPackets() override;

  absl::Status WritePackets(std::vector<Packet> packets) override;

  absl::Status Connect(Endpoint dest) override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override {};

 private:
  SOCKET socket_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SOCKET_H_
