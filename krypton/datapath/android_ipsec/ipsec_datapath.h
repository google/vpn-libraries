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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_DATAPATH_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_DATAPATH_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_packet_forwarder.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Manages the Ipsec data path.
// Class is thread safe.
class IpSecDatapath : public DatapathInterface,
                      public IpSecPacketForwarder::NotificationInterface {
 public:
  // Extension to VpnService with methods needed specifically for Android IpSec.
  class IpSecVpnServiceInterface : public virtual VpnServiceInterface {
   public:
    // Creates a protected FD and a socket object for the network connection.
    virtual absl::StatusOr<std::unique_ptr<IpSecSocketInterface>>
    CreateProtectedNetworkSocket(const NetworkInfo& network_info,
                                 const Endpoint& endpoint) = 0;

    virtual TunnelInterface* GetTunnel() = 0;

    virtual absl::Status ConfigureIpSec(const IpSecTransformParams& params) = 0;

    virtual void DisableKeepalive() = 0;
  };

  explicit IpSecDatapath(const KryptonConfig& config,
                         utils::LooperThread* looper,
                         IpSecVpnServiceInterface* vpn_service)
      : config_(config),
        notification_thread_(looper),
        vpn_service_(vpn_service) {}
  ~IpSecDatapath() override = default;

  // Initialize the Ipsec data path.
  // TODO: Remove AddEgressResponse and Bridge specific stuff from
  // Start method.
  absl::Status Start(const AddEgressResponse& egress_response,
                     const TransformParams& params) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Terminate the data path connection.
  void Stop() override ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             std::optional<NetworkInfo> network_info,
                             int counter) override ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status SetKeyMaterials(const TransformParams& params) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void IpSecPacketForwarderFailed(const absl::Status&) override;

  void IpSecPacketForwarderPermanentFailure(const absl::Status&) override;

  void IpSecPacketForwarderConnected() override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

 private:
  void ShutdownIpSecPacketForwarder() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Mutex mutex_;

  KryptonConfig config_;

  utils::LooperThread* notification_thread_;
  IpSecVpnServiceInterface* vpn_service_;

  std::optional<IpSecTransformParams> key_material_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<IpSecPacketForwarder> forwarder_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<IpSecSocketInterface> network_socket_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_DATAPATH_H_
