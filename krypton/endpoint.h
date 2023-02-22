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

#ifndef PRIVACY_NET_KRYPTON_ENDPOINT_H_
#define PRIVACY_NET_KRYPTON_ENDPOINT_H_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

#include <string>

#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

// The remote endpoint that Krypton connects to.
class Endpoint {
 public:
  struct SockAddrInfo {
    sockaddr_storage sockaddr;
    socklen_t socklen;
  };

  // Endpoint that is formatted string using `address:port` for IPv4 and
  // `[address]:port` for IPv6.
  Endpoint(const std::string host_port, const std::string address, int port,
           IPProtocol ip_protocol)
      : endpoint_string_(host_port),
        address_(address),
        port_(port),
        ip_protocol_(ip_protocol) {}

  // IP address of the endpoint.
  const std::string& address() const { return address_; }

  // Port of the endpoint.
  int port() const { return port_; }

  // The protocol of the packet data.
  IPProtocol ip_protocol() const { return ip_protocol_; }

  absl::StatusOr<SockAddrInfo> GetSockAddr() const;

  // Formatted string using `address:port` for IPv4 and `[address]:port` for
  // IPv6.
  const std::string& ToString() const { return endpoint_string_; }

  bool operator==(const Endpoint& other) const {
    return address_ == other.address_ && port_ == other.port_ &&
           ip_protocol_ == other.ip_protocol_;
  }

  bool operator!=(const Endpoint& other) const {
    return address_ != other.address_ || port_ != other.port_ ||
           ip_protocol_ != other.ip_protocol_;
  }

 private:
  std::string endpoint_string_;
  std::string address_;
  int port_;
  // The protocol of the packet data.
  IPProtocol ip_protocol_;
};

// Creates an endpoint from a formatted string.
absl::StatusOr<Endpoint> GetEndpointFromHostPort(std::string host_port);

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_ENDPOINT_H_
