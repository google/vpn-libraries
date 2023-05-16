// Copyright 2022 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TUNNEL_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TUNNEL_INTERFACE_H_

#include <vector>

#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Interface for tunnel.
class TunnelInterface {
 public:
  virtual ~TunnelInterface() = default;

  // Stops reading from the tunnel, but does not close the underlying fd.
  virtual absl::Status CancelReadPackets() = 0;

  // Make a blocking read from the tunnel.
  // Returns an error if the read fails.
  virtual absl::StatusOr<std::vector<Packet>> ReadPackets() = 0;

  // Make a blocking write to the tunnel.
  // Returns an error if the write fails.
  virtual absl::Status WritePackets(std::vector<Packet> packets) = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TUNNEL_INTERFACE_H_
