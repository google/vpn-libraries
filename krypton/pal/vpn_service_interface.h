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

#ifndef PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_

#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/statusor.h"

// Interface for Krypton to interact with the system-level VPN service API.
namespace privacy {
namespace krypton {

enum class IPProtocol {
  kUnknown = 0,
  kIPv4 = 1,
  kIPv6 = 2,
};

// Represents a single network packet.
struct Packet {
  // The raw bytes data for a single packet.
  absl::string_view data;
  // The protocol of the packet data.
  IPProtocol protocol;
};

// An interface for a two-way channel that can read and write packets.
class PacketPipe {
 public:
  virtual ~PacketPipe() {}

  virtual absl::Status WritePacket(Packet packets) = 0;
  virtual void ReadPacket(void handler(absl::Status status,
                                       Packet packets)) = 0;

  // Returns a file descriptor if this tunnel is backed by one, else an error.
  virtual absl::StatusOr<int> GetFd() const = 0;

  // Closing the VPN's tunnel should also be the signal to the system that
  // traffic should stop going through the VPN.
  virtual void Close() = 0;

  // Returns a human-readable description of the pipe, for debugging.
  virtual std::string DebugString() = 0;
};

class VpnServiceInterface {
 public:
  VpnServiceInterface() = default;
  virtual ~VpnServiceInterface() = default;

  // Establishes the tunnel.
  virtual absl::StatusOr<std::unique_ptr<PacketPipe>> CreateTunnel(
      const TunFdData& tun_fd_data) = 0;

  // Creates network sockets.
  virtual absl::StatusOr<std::unique_ptr<PacketPipe>>
  CreateProtectedNetworkSocket(const NetworkInfo& network_info) = 0;

  virtual absl::Status ConfigureIpSec(const IpSecTransformParams& params) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_
