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

#ifndef PRIVACY_NET_KRYPTON_UTILS_IP_RANGE_H_
#define PRIVACY_NET_KRYPTON_UTILS_IP_RANGE_H_

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace utils {

// Returns just the host part from a string containing a host and optional port.
absl::StatusOr<std::string> GetHostFromHostPort(absl::string_view host_port);

absl::StatusOr<std::string> ResolveIPV4Address(const std::string& hostname);

// Checks if the string is a dotted notation of IPv4 address.
bool IsValidV4Address(absl::string_view ip) MUST_USE_RESULT;

// Checks if the string is a dotted notation of IPv6 address.
bool IsValidV6Address(absl::string_view ip) MUST_USE_RESULT;

// Parses IPRange in the format of A.B.C.D/29 or A:B::C:D/64 to its native
// form. Not thread safe.
class IPRange {
 public:
  static absl::StatusOr<IPRange> Parse(absl::string_view ip_range);

  // IP Family AF_INET or AF_INET6
  int family() const { return family_; }

  // Address in dotted notation.
  std::string address() const { return address_; }

  // Prefix.
  absl::optional<int> prefix() const { return prefix_; }

  // Returns the Host:port with IPv4:port or [IPv6]:port
  std::string HostPortString(int port);

  absl::Status GenericAddress(int port, sockaddr_storage* addr_out,
                              socklen_t* size_out);

 private:
  IPRange() = default;
  absl::Status ParseInternal(absl::string_view ip_range);

  int family_;
  std::string address_;
  absl::optional<int> prefix_;
};

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_IP_RANGE_H_
