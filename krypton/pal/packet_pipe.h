// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_PAL_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_PAL_PACKET_PIPE_H_

#include <functional>
#include <string>
#include <vector>

#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

// An interface for a two-way channel that can read and write packets.
class PacketPipe {
 public:
  virtual ~PacketPipe() {}

  // Writes a batch of packets to the pipe.
  virtual absl::Status WritePackets(std::vector<Packet> packets) = 0;

  // Sets a handler that will be called whenever new packets are available.
  // If the status is ever not OK, then no more packets will be delivered.
  virtual void ReadPackets(
      std::function<bool(absl::Status, std::vector<Packet>)> handler) = 0;

  // Returns a file descriptor if this tunnel is backed by one, else an error.
  virtual absl::StatusOr<int> GetFd() const = 0;

  // Tells the pipe to stop reading packets.
  virtual absl::Status StopReadingPackets() = 0;

  // Closing the VPN's tunnel should also be the signal to the system that
  // traffic should stop going through the VPN.
  virtual void Close() = 0;

  // Returns a human-readable description of the pipe, for debugging.
  virtual std::string DebugString() = 0;

  // Populates debug info for the packet pipe.
  virtual void GetDebugInfo(PacketPipeDebugInfo* debug_info) {}
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_PACKET_PIPE_H_
