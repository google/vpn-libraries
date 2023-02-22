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

#include "privacy/net/krypton/endpoint.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/numbers.h"

namespace privacy {
namespace krypton {

absl::StatusOr<Endpoint::SockAddrInfo> Endpoint::GetSockAddr() const {
  SockAddrInfo sockaddr_info;
  PPN_ASSIGN_OR_RETURN(auto ip_range, utils::IPRange::Parse(address_));
  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(port_, &sockaddr_info.sockaddr,
                                              &sockaddr_info.socklen));
  return sockaddr_info;
}

absl::StatusOr<Endpoint> GetEndpointFromHostPort(const std::string host_port) {
  std::string host;
  std::string port_string;
  PPN_RETURN_IF_ERROR(utils::ParseHostPort(host_port, &host, &port_string));

  IPProtocol ip_protocol = IPProtocol::kUnknown;
  if (utils::IsValidV4Address(host_port)) {
    ip_protocol = IPProtocol::kIPv4;
  } else if (utils::IsValidV6Address(host_port)) {
    ip_protocol = IPProtocol::kIPv6;
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("invalid endpoint: ", host_port));
  }

  if (port_string.empty()) {
    return absl::InvalidArgumentError("endpoint missing port");
  }
  int port = 0;
  if (!absl::SimpleAtoi(port_string, &port)) {
    return absl::InvalidArgumentError(
        absl::StrCat("endpoint has invalid port ", port_string));
  }

  return Endpoint(host_port, host, port, ip_protocol);
}

}  // namespace krypton
}  // namespace privacy
