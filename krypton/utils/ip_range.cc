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

#include "privacy/net/krypton/utils/ip_range.h"

#include <cstring>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <optional>
#include <string>
#include <vector>

#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/numbers.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_split.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace utils {

absl::Status ParseHostPort(absl::string_view host_port, std::string* host,
                           std::string* port) {
  if (!host_port.empty() && host_port[0] == '[') {
    // Parse a bracketed host, typically an IPv6 literal.
    auto rbracket = host_port.rfind(']');
    if (rbracket == absl::string_view::npos) {
      return absl::InvalidArgumentError(
          absl::StrCat("Unterminated [ in host-post: ", host_port));
    }
    if (rbracket + 1 < host_port.size()) {
      if (host_port[rbracket + 1] != ':') {
        return absl::InvalidArgumentError(
            absl::StrCat("Missing : after ] in host-post: ", host_port));
      }
    }
    if (host != nullptr) {
      *host = std::string(absl::ClippedSubstr(host_port, 1, rbracket - 1));
    }
    if (port != nullptr) {
      *port = std::string(absl::ClippedSubstr(host_port, rbracket + 2));
    }
    return absl::OkStatus();
  }

  const auto colon = host_port.find(':');
  if (colon != absl::string_view::npos &&
      host_port.find(':', colon + 1) == absl::string_view::npos) {
    // Exactly 1 colon.  Split into host:port.
    if (host != nullptr) {
      *host = std::string(absl::ClippedSubstr(host_port, 0, colon));
    }
    if (port != nullptr) {
      *port = std::string(absl::ClippedSubstr(host_port, colon + 1));
    }
    return absl::OkStatus();
  }
  // 0 or 2+ colons.  Bare hostname or IPv6 literal.
  if (host != nullptr) {
    *host = std::string(host_port);
  }
  if (port != nullptr) {
    *port = "";
  }
  return absl::OkStatus();
}

bool IsValidV4Address(absl::string_view ip) {
  // Checks whether IPv4 dotted notation '.' is present.

  if (!absl::StrContains(ip, ".")) {
    return false;
  }

  unsigned char buf[sizeof(struct in6_addr)];
  std::string host;
  auto status = ParseHostPort(ip, &host, nullptr);
  if (!status.ok()) {
    return false;
  }

  // inet_pton checks if the string is valid ip.
  if (inet_pton(AF_INET, host.c_str(), buf) != 0) {
    return true;
  }
  return false;
}

bool IsValidV6Address(absl::string_view ip) {
  // Checks whether IPv6 dotted notation ':' is present.
  if (!absl::StrContains(ip, ":")) {
    return false;
  }

  unsigned char buf[sizeof(struct in6_addr)];
  std::string host;
  auto status = ParseHostPort(ip, &host, nullptr);
  if (!status.ok()) {
    return false;
  }

  // inet_pton checks if the string is valid ip.
  if (inet_pton(AF_INET6, host.c_str(), buf) != 0) {
    return true;
  }
  return false;
}

absl::StatusOr<IPRange> IPRange::Parse(absl::string_view ip_range_string) {
  IPRange ip_range;
  PPN_RETURN_IF_ERROR(ip_range.ParseInternal(ip_range_string));
  return ip_range;
}

absl::StatusOr<IPRange> IPRange::FromProto(const TunFdData::IpRange& proto) {
  IPRange ip_range;
  switch (proto.ip_family()) {
    case TunFdData::IpRange::IPV4:
      ip_range.family_ = AF_INET;
      break;
    case TunFdData::IpRange::IPV6:
      ip_range.family_ = AF_INET6;
      break;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unknown IpFamily: ", proto.ip_family()));
  }
  ip_range.address_ = proto.ip_range();
  if (proto.has_prefix()) {
    ip_range.prefix_ = proto.prefix();
  }
  return ip_range;
}

std::string IPRange::HostPortString(int port) {
  if (family_ == AF_INET) {
    return absl::StrCat(address_, ":", port);
  }
  return absl::StrCat("[", address_, "]", ":", port);
}

absl::Status IPRange::ParseInternal(absl::string_view ip_range) {
  const std::vector<std::string> splits = absl::StrSplit(ip_range, '/');

  if (ip_range.empty()) {
    return absl::InvalidArgumentError("IP address cannot be null");
  }
  // Valid format is an <ip_string> and an optional prefix.
  if (splits.empty() || splits.size() > 2) {
    return absl::InvalidArgumentError(
        absl::StrCat("IPRange ", ip_range, " is not valid"));
  }

  const std::string& ip = splits.front();
  if (IsValidV4Address(ip)) {
    family_ = AF_INET;
    address_ = ip;
    if (splits.size() == 2) {
      int prefix;
      if (!absl::SimpleAtoi(splits.back(), &prefix)) {
        return absl::InvalidArgumentError("Invalid IP address range.");
      }
      if (prefix < 1 || prefix > 32) {
        return absl::InvalidArgumentError("IP address range out of range.");
      }
      prefix_ = prefix;
    }
    return absl::OkStatus();
  }

  if (IsValidV6Address(ip)) {
    family_ = AF_INET6;
    address_ = ip;
    if (splits.size() == 2) {
      int prefix;
      if (!absl::SimpleAtoi(splits.back(), &prefix)) {
        return absl::InvalidArgumentError("Invalid IP address range.");
      }
      if (prefix < 1 || prefix > 128) {
        return absl::InvalidArgumentError("IP address range out of range.");
      }
      prefix_ = prefix;
    }
    return absl::OkStatus();
  }
  return absl::FailedPreconditionError("IPRange is neither v4 or v6");
}

absl::Status IPRange::GenericAddress(int port, sockaddr_storage* addr_out,
                                     socklen_t* size_out) {
  DCHECK(size_out != nullptr);
  memset(addr_out, 0, sizeof(sockaddr_storage));

  switch (family_) {
    case AF_INET: {
      auto* addr = reinterpret_cast<sockaddr_in*>(addr_out);
      *size_out = sizeof(*addr);
      addr->sin_family = AF_INET;
      in_addr addr4;
      if (inet_pton(AF_INET, address_.c_str(), &addr4) < 1) {
        return absl::InternalError("Cannot convert IP address");
      }
      addr->sin_addr = addr4;
      addr->sin_port = htons(port);
      return absl::OkStatus();
    } break;
    case AF_INET6: {
      sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(addr_out);
      *size_out = sizeof(*addr);
      addr->sin6_family = AF_INET6;
      in6_addr addr6;
      if (inet_pton(AF_INET6, address_.c_str(), &addr6) < 1) {
        return absl::InternalError("Cannot convert IP address");
      }
      addr->sin6_addr = addr6;
      addr->sin6_port = htons(port);
      return absl::OkStatus();
    } break;
  }
  return absl::InvalidArgumentError("Address is neither v4 or v6");
}

absl::StatusOr<std::string> ResolveIPAddress(const std::string& hostname) {
  struct addrinfo hints = {};

  // Get the addrinfo for the hostname.
  struct addrinfo* info = nullptr;
  int err = getaddrinfo(hostname.c_str(), /*service=*/nullptr, &hints, &info);
  if (err != 0) {
    return absl::InternalError(
        absl::StrCat("getaddrinfo error: ", gai_strerror(err)));
  }
  if (info == nullptr) {
    return absl::NotFoundError("Cannot convert host to IP address");
  }
  absl::Cleanup free_info([info] { freeaddrinfo(info); });

  // Convert the addrinfo into a dotted number string.
  // The max length for IPv6 is long enough for either IPv4 or IPv6.
  char ip[INET6_ADDRSTRLEN];
  err = getnameinfo(info->ai_addr, info->ai_addrlen, ip, INET6_ADDRSTRLEN,
                    /*service=*/nullptr, 0, NI_NUMERICHOST);
  if (err != 0) {
    return absl::InternalError(
        absl::StrCat("getnameinfo error: ", gai_strerror(err)));
  }
  return ip;
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
