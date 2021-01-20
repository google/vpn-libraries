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

#ifndef PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_

#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace jni {

class VpnService : public VpnServiceInterface {
 public:
  VpnService() = default;
  ~VpnService() override = default;

  // TUN fd creation
  absl::StatusOr<std::unique_ptr<PacketPipe>> CreateTunnel(
      const TunFdData& tun_fd_data) override;

  // Network fd creation
  absl::StatusOr<std::unique_ptr<PacketPipe>> CreateProtectedNetworkSocket(
      const NetworkInfo& network_info) override;

  absl::Status ConfigureIpSec(const IpSecTransformParams& params) override;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_
