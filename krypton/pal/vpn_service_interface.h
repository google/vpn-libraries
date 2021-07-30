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

#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/statusor.h"

// Interface for Krypton to interact with the system-level VPN service API.
namespace privacy {
namespace krypton {

// An interface for a two-way channel that can read and write packets.
class PacketPipe {
 public:
  virtual ~PacketPipe() {}

  // Writes a packet to the pipe.
  virtual absl::Status WritePacket(const Packet& packet) = 0;

  // Sets a handler that will be called whenever a new packet is available.
  // If the status is ever not OK, then no more packets will be delivered.
  virtual void ReadPackets(
      std::function<bool(absl::Status, Packet)> handler) = 0;

  // Returns a file descriptor if this tunnel is backed by one, else an error.
  virtual absl::StatusOr<int> GetFd() const = 0;

  // Tells the pipe to stop reading packets.
  virtual absl::Status StopReadingPackets() = 0;

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
  // Note: This method only works on Android.
  virtual absl::StatusOr<int> CreateProtectedNetworkSocket(
      const NetworkInfo& network_info) = 0;

  // Creates a UDP connection to an endpoint on the network.
  virtual absl::StatusOr<std::unique_ptr<PacketPipe>> CreateNetworkPipe(
      const NetworkInfo& network_info, const Endpoint&) = 0;

  // Configures IpSec.
  // Note: This method only works on Android.
  virtual absl::Status ConfigureIpSec(const IpSecTransformParams& params) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_VPN_SERVICE_INTERFACE_H_
