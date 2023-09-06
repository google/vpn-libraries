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

#include <cstdint>
#include <memory>
#include <optional>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/android_ipsec/health_check.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_packet_forwarder.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Manages the Ipsec data path.
// Class is thread safe.
class IpSecDatapath : public DatapathInterface,
                      public IpSecPacketForwarder::NotificationInterface,
                      public MtuTrackerInterface::NotificationInterface,
                      public HealthCheck::NotificationInterface {
 public:
  // Extension to VpnService with methods needed specifically for Android IpSec.
  class IpSecVpnServiceInterface : public virtual VpnServiceInterface {
   public:
    // Creates a protected FD and a socket object for the network connection.
    virtual absl::StatusOr<std::unique_ptr<IpSecSocketInterface>>
    CreateProtectedNetworkSocket(const NetworkInfo& network_info,
                                 const Endpoint& endpoint) = 0;

    virtual absl::StatusOr<std::unique_ptr<IpSecSocketInterface>>
    CreateProtectedNetworkSocket(
        const NetworkInfo& network_info, const Endpoint& endpoint,
        const Endpoint& mss_mtu_detection_endpoint,
        std::unique_ptr<MtuTrackerInterface> mtu_tracker) = 0;

    virtual absl::StatusOr<TunnelInterface*> GetTunnel() = 0;

    virtual absl::Status ConfigureIpSec(const IpSecTransformParams& params) = 0;

    virtual void DisableKeepalive() = 0;
  };

  explicit IpSecDatapath(const KryptonConfig& config,
                         utils::LooperThread* looper,
                         IpSecVpnServiceInterface* vpn_service,
                         TimerManager* timer_manager)
      : config_(config),
        notification_thread_(looper),
        vpn_service_(vpn_service),
        ipv4_tcp_mss_endpoint_("", "", 0, IPProtocol::kUnknown),
        ipv6_tcp_mss_endpoint_("", "", 0, IPProtocol::kUnknown),
        rekey_needed_(false),
        datapath_established_(false),
        looper_("IpSecDatapath Looper"),
        curr_forwarder_id_(0),
        health_check_(config, timer_manager, this, &looper_) {}
  ~IpSecDatapath() override;

  // Initialize the Ipsec data path.
  absl::Status Start(const AddEgressResponse& egress_response,
                     const TransformParams& params) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Terminate the data path connection.
  void Stop() override ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             const NetworkInfo& network_info,
                             int counter) override ABSL_LOCKS_EXCLUDED(mutex_);

  // Stops any processing that may try to access the current tunnel. If the
  // datapath is not stopped, then this must be called before creating a new
  // tunnel with VpnService.CreateTunnel(). When VpnService.CreateTunnel() is
  // called it will delete the existing tunnel that is being used by the
  // datapath.
  void PrepareForTunnelSwitch() ABSL_LOCKS_EXCLUDED(mutex_) override;

  // Uses the newest tunnel to start processing that was stopped by
  // PrepareForTunnelSwitch().
  void SwitchTunnel() ABSL_LOCKS_EXCLUDED(mutex_) override;

  absl::Status SetKeyMaterials(const TransformParams& params) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void IpSecPacketForwarderFailed(const absl::Status& status, int forwarder_id)
      ABSL_LOCKS_EXCLUDED(mutex_) override;

  void IpSecPacketForwarderPermanentFailure(const absl::Status& status,
                                            int forwarder_id)
      ABSL_LOCKS_EXCLUDED(mutex_) override;

  void IpSecPacketForwarderConnected(int forwarder_id)
      ABSL_LOCKS_EXCLUDED(mutex_) override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

  void UplinkMtuUpdated(int uplink_mtu, int tunnel_mtu) override;

  void DownlinkMtuUpdated(int downlink_mtu) override;

  void HealthCheckFailed(const absl::Status& status) override;

 private:
  void StopInternal() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartUpIpSecPacketForwarder() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void ShutDownIpSecPacketForwarder(bool close_network_socket)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void CloseNetworkSocket() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Verify the provided forwarder ID matches the ID of the current forwarder
  bool IsForwarderNotificationValid(int forwarder_id)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void NotifyDatapathFailed(const absl::Status& status);

  void NotifyDatapathPermanentFailure(const absl::Status& status);

  absl::Mutex mutex_;

  KryptonConfig config_;

  utils::LooperThread* notification_thread_;  // Not owned.
  IpSecVpnServiceInterface* vpn_service_;     // Not owned.

  Endpoint ipv4_tcp_mss_endpoint_;
  Endpoint ipv6_tcp_mss_endpoint_;

  bool rekey_needed_ ABSL_GUARDED_BY(mutex_);
  bool datapath_established_ ABSL_GUARDED_BY(mutex_);

  // The looper_ must outlive both network_socket_ and forwarder_. The
  // forwarder_ directly relies on looper_, while the network_socket_ will own
  // an MTU tracker, which relies on looper_.
  utils::LooperThread looper_;

  std::optional<IpSecTransformParams> key_material_ ABSL_GUARDED_BY(mutex_);
  int curr_forwarder_id_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<IpSecPacketForwarder> forwarder_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<IpSecSocketInterface> network_socket_ ABSL_GUARDED_BY(mutex_);
  HealthCheck health_check_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_DATAPATH_H_
