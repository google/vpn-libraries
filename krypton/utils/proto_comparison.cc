// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
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

#include "privacy/net/krypton/utils/proto_comparison.h"

namespace privacy {
namespace krypton {
namespace utils {

bool IpRangeEquiv(const TunFdData_IpRange& ipr1,
                  const TunFdData_IpRange& ipr2) {
  if (ipr1.ip_family() != ipr2.ip_family()) {
    return false;
  }
  if (ipr1.ip_range() != ipr2.ip_range()) {
    return false;
  }
  if (ipr1.prefix() != ipr2.prefix()) {
    return false;
  }
  return true;
}

bool TunFdDataEquiv(const TunFdData& td1, const TunFdData& td2) {
  if (td1.has_session_name() != td2.has_session_name()) {
    return false;
  }
  if (td1.session_name() != td2.session_name()) {
    return false;
  }
  if (td1.has_mtu() != td2.has_mtu()) {
    return false;
  }
  if (td1.mtu() != td2.mtu()) {
    return false;
  }
  if (td1.is_metered() != td2.is_metered()) {
    return false;
  }
  if (td1.send_buffer_size() != td2.send_buffer_size()) {
    return false;
  }
  if (td1.receive_buffer_size() != td2.receive_buffer_size()) {
    return false;
  }
  if (td1.tunnel_ip_addresses_size() != td2.tunnel_ip_addresses_size()) {
    return false;
  }
  for (size_t i = 0; i < td1.tunnel_ip_addresses_size(); i++) {
    if (!IpRangeEquiv(td1.tunnel_ip_addresses(i), td2.tunnel_ip_addresses(i))) {
      return false;
    }
  }
  if (td1.tunnel_dns_addresses_size() != td2.tunnel_dns_addresses_size()) {
    return false;
  }
  for (size_t i = 0; i < td1.tunnel_dns_addresses_size(); i++) {
    if (!IpRangeEquiv(td1.tunnel_dns_addresses(i),
                      td2.tunnel_dns_addresses(i))) {
      return false;
    }
  }
  if (td1.tunnel_routes_size() != td2.tunnel_routes_size()) {
    return false;
  }
  for (size_t i = 0; i < td1.tunnel_routes_size(); i++) {
    if (!IpRangeEquiv(td1.tunnel_routes(i), td2.tunnel_routes(i))) {
      return false;
    }
  }
  return true;
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
