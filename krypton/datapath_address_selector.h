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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ADDRESS_SELECTOR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ADDRESS_SELECTOR_H_

#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {

/**
 * Class that takes addresses from the EgressManager and doles them out to the
 * Session one at a time, in the order we want to try them.
 */
class DatapathAddressSelector {
 public:
  DatapathAddressSelector() = default;
  ~DatapathAddressSelector() = default;

  // Resets the selector with a new set of addresses to try.
  // This should be called whenever the datapath is ready to reconnect.
  void Reset(const std::vector<std::string>& addresses,
             absl::optional<NetworkInfo> network_info)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the next address to try. Every time this is called, it will
  // advance to the next address to try. When no more addresses are available,
  // it will return a RESOURCE_EXCEEDED Status.
  absl::StatusOr<Endpoint> SelectDatapathAddress() ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns true if there are more datapath addresses that could be tried.
  bool HasMoreAddresses() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  mutable absl::Mutex mutex_;
  std::vector<std::string> addresses_ ABSL_GUARDED_BY(mutex_);
  int datapath_attempts_ ABSL_GUARDED_BY(mutex_) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ADDRESS_SELECTOR_H_
