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

#include "privacy/net/krypton/datapath_address_selector.h"

#include "base/logging.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"

namespace privacy {
namespace krypton {

constexpr int MAX_ATTEMPTS_PER_ADDRESS_FAMILY = 2;

void DatapathAddressSelector::Reset(const std::vector<std::string>& addresses,
                                    absl::optional<NetworkInfo> network_info) {
  absl::MutexLock l(&mutex_);
  datapath_attempts_ = 0;

  if (!network_info) {
    LOG(WARNING)
        << "Resetting datapath address selector with no network available.";
  }

  // To simplify the selection logic, addresses_ stores a list of addresses
  // sorted and repeated according to how many times we want to retry them.

  // First, split the addresses into IPv4 and IPv6.
  std::vector<std::string> ipv6;
  std::vector<std::string> ipv4;
  for (const auto& ip : addresses) {
    if (utils::IsValidV6Address(ip)) {
      if (!network_info || network_info->address_family() == NetworkInfo::V6 ||
          network_info->address_family() == NetworkInfo::V4V6) {
        ipv6.push_back(ip);
      }
    } else if (utils::IsValidV4Address(ip)) {
      if (!network_info || network_info->address_family() == NetworkInfo::V4 ||
          network_info->address_family() == NetworkInfo::V4V6) {
        ipv4.push_back(ip);
      }
    } else {
      LOG(ERROR) << "Datapath address is neither IPv4 nor IPv6: " << ip;
    }
  }

  // Then alternate between IPv6 and IPv4.
  std::vector<std::string> interlaced;
  int i = 0;
  for (; i < ipv6.size() && i < ipv4.size(); i++) {
    interlaced.push_back(ipv6[i]);
    interlaced.push_back(ipv4[i]);
  }

  // Gather up the remaining addresses, which will either all be V4 or all V6.
  while (i < ipv6.size()) {
    interlaced.push_back(ipv6[i++]);
  }
  while (i < ipv4.size()) {
    interlaced.push_back(ipv4[i++]);
  }

  // Then, retry each address a couple of times.
  addresses_.clear();
  for (int j = 0; j < MAX_ATTEMPTS_PER_ADDRESS_FAMILY; j++) {
    for (auto& ip : interlaced) {
      addresses_.push_back(ip);
    }
  }
}

absl::StatusOr<Endpoint> DatapathAddressSelector::SelectDatapathAddress() {
  absl::MutexLock l(&mutex_);

  if (addresses_.empty()) {
    return absl::FailedPreconditionError("No Egress node socket address found");
  }

  if (datapath_attempts_ >= addresses_.size()) {
    return absl::ResourceExhaustedError(
        "Max reattempts have been reached on both IPv4 and IPv6");
  }

  auto ip = addresses_[datapath_attempts_++];
  LOG(INFO) << "Attempting datapath " << ip << " on attempt "
            << datapath_attempts_;
  return GetEndpointFromHostPort(ip);
}

bool DatapathAddressSelector::HasMoreAddresses() {
  absl::MutexLock l(&mutex_);
  return datapath_attempts_ < addresses_.size();
}

}  // namespace krypton
}  // namespace privacy
