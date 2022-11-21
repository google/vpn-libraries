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

#ifndef PRIVACY_NET_KRYPTON_SOCKET_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_SOCKET_INTERFACE_H_

#include <vector>

#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

// Interface for network socket.
class SocketInterface {
 public:
  virtual ~SocketInterface() = default;

  // Shuts down and closes the socket. The socket cannot be restarted after
  // being stopped.
  virtual absl::Status Close() = 0;

  // Make a blocking read from the socket.
  // Returns an error if the read fails.
  virtual absl::StatusOr<std::vector<Packet>> ReadPackets() = 0;

  // Make a blocking write to the socket.
  // Returns an error if the write fails.
  virtual absl::Status WritePackets(std::vector<Packet> packets) = 0;

  // Connects the socket to a remote endpoint.
  // Possible errors are from the endpoint not being parseable as an IPRange or
  // IP address, or if the underlying connect operation fails.
  virtual absl::Status Connect(Endpoint dest) = 0;

  // Populate DatapathDebugInfo proto with relevant socket stats.
  virtual void GetDebugInfo(DatapathDebugInfo* debug_info) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_SOCKET_INTERFACE_H_
