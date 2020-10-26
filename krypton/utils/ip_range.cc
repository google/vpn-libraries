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

#include "privacy/net/krypton/utils/ip_range.h"

#include <arpa/inet.h>
#include <linux/in6.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <optional>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/utils/status.h"
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

absl::StatusOr<std::string> GetHostFromHostPort(absl::string_view host_port) {
  // This functions does not verify that the port is valid, but just strips it.

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
    return std::string(absl::ClippedSubstr(host_port, 1, rbracket - 1));
  }

  const auto colon = host_port.find(':');
  if (colon != absl::string_view::npos &&
      host_port.find(':', colon + 1) == absl::string_view::npos) {
    // Exactly 1 colon.  Split into host:port.
    return std::string(host_port.substr(0, colon));
  }
  // 0 or 2+ colons.  Bare hostname or IPv6 literal.
  return std::string(host_port);
}

bool IsValidV4Address(absl::string_view ip) {
  // Checks whether IPv4 dotted notation '.' is present.

  if (!absl::StrContains(ip, ".")) {
    return false;
  }

  unsigned char buf[sizeof(struct in6_addr)];
  auto host = GetHostFromHostPort(ip);
  if (!host.ok()) {
    return false;
  }

  // inet_pton checks if the string is valid ip.
  if (inet_pton(AF_INET, host.value().c_str(), buf) != 0) {
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
  auto host = GetHostFromHostPort(ip);
  if (!host.ok()) {
    return false;
  }

  // inet_pton checks if the string is valid ip.
  if (inet_pton(AF_INET6, host.value().c_str(), buf) != 0) {
    return true;
  }
  return false;
}

absl::StatusOr<IPRange> IPRange::Parse(absl::string_view ip_range_string) {
  IPRange ip_range;
  PPN_RETURN_IF_ERROR(ip_range.ParseInternal(ip_range_string));
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

  auto ip = splits.front();
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
  return absl::InvalidArgumentError(("Address is neither v4 or v6"));
}

absl::StatusOr<std::string> ResolveIPV4Address(const std::string& hostname) {
  // Temporary memory allocation that is needed for gethostbyname_r to work on.
  // There is no particular reason this has to be 8192.
  static const int kTmpLen = 8192;
  struct hostent hbuf, *output;
  char tmp[kTmpLen];
  int error_number;

  auto get_host_status = gethostbyname_r(hostname.c_str(), &hbuf, tmp, kTmpLen,
                                         &output, &error_number);
  if (get_host_status != 0) {
    return absl::UnavailableError(
        absl::StrCat("gethostbyname_r error: ", hstrerror(error_number)));
  }
  // Return the first address.
  if (output->h_addr_list[0] != nullptr) {
    return inet_ntoa(*reinterpret_cast<in_addr*>(output->h_addr_list[0]));
  }

  return absl::NotFoundError("Cannot convert host to IP address");
}
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
