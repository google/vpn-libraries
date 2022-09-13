// Copyright 2021 Google LLC
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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNDATAPATH_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNDATAPATH_H_

#include <atomic>

#include "google/protobuf/duration.proto.h"
#include "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketForwarder.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/datapath/packet_forwarder.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Manages the IPSec datapath on iOS.
//
// For IPSec datapath on Android, use datapath/android_ipsec/ipsec_datapath.
//
// This class is thread safe.
class PPNDatapath : public DatapathInterface,
                    public PacketForwarderNotificationInterface {
 public:
  // An interface for ipsec-specific extensions to the VpnService interface.
  class PPNDatapathVpnServiceInterface : public virtual VpnServiceInterface {
   public:
    // Creates a UDP connection to an endpoint on the network.
    virtual absl::StatusOr<NWUDPSession*> CreateUDPSession(const NetworkInfo&,
                                                           const Endpoint&) = 0;

    // Verifies the tunnel connection is still up.
    virtual absl::Status CheckConnection() = 0;

    // Gets the current tunnel.
    virtual NEPacketTunnelFlow* GetPacketTunnelFlow() = 0;
  };

  PPNDatapath(const KryptonConfig& config, utils::LooperThread* looper,
              PPNDatapathVpnServiceInterface* vpn_service,
              TimerManager* timer_manager)
      : config_(config),
        notification_thread_(looper),
        vpn_service_(vpn_service),
        timer_manager_(timer_manager),
        periodic_health_check_enabled_(config.periodic_health_check_enabled()),
        periodic_health_check_duration_(
            absl::Seconds(config.periodic_health_check_duration().seconds())) {
    connected_.clear();
  }
  ~PPNDatapath() override = default;
  PPNDatapath(const PPNDatapath&) = delete;
  PPNDatapath(PPNDatapath&&) = delete;
  PPNDatapath& operator=(const PPNDatapath&) = delete;
  PPNDatapath& operator=(PPNDatapath&&) = delete;

  // Configs the datapath.
  //
  // Datapath will not run until `SwitchNetwork` is called.
  absl::Status Start(const AddEgressResponse& egress_response,
                     const TransformParams& params) override;

  // Terminates the datapath connection.
  void Stop() override;

  // Establishes the VPN tunnel.
  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             absl::optional<NetworkInfo> network_info,
                             int counter) override;

  // Updates crypto keys.
  absl::Status SetKeyMaterials(const TransformParams& params) override;

  void PacketForwarderFailed(const absl::Status&) override;

  void PacketForwarderPermanentFailure(const absl::Status&) override;

  void PacketForwarderConnected() override;

  void PacketForwarderHasBetterPath(NWUDPSession* udp_session) override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

 private:
  absl::Mutex mutex_;
  privacy::krypton::KryptonConfig config_;
  utils::LooperThread* notification_thread_;     // Not owned by this class.
  PPNDatapathVpnServiceInterface* vpn_service_;  // Not owned by this class.
  TimerManager* timer_manager_;                  // Not owned by this class.

  // This is only used until it is stopped, and then reset to nil.
  PPNPacketForwarder* packet_forwarder_ ABSL_GUARDED_BY(mutex_);
  // A looper for the packet forwarder to use to send events up to this class.
  utils::LooperThread packet_forwarder_looper_{"PacketForwarder"};

  // Whether the datapath is connected. This is used to make sure we don't send
  // out redundant "connected" notifications if we're already connected.
  std::atomic_flag connected_;

  absl::optional<uint32_t> uplink_spi_ ABSL_GUARDED_BY(mutex_);
  absl::optional<TransformParams> key_material_ ABSL_GUARDED_BY(mutex_);
  absl::optional<Endpoint> endpoint_ ABSL_GUARDED_BY(mutex_);
  absl::optional<NetworkInfo> network_info_ ABSL_GUARDED_BY(mutex_);

  int datapath_connecting_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int health_check_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_connecting_count_ ABSL_GUARDED_BY(mutex_) = 0;

  const bool periodic_health_check_enabled_;
  const absl::Duration periodic_health_check_duration_;
  std::shared_ptr<std::atomic_bool> health_check_cancelled_
      ABSL_GUARDED_BY(mutex_);
  utils::LooperThread healthcheck_looper_{"HealthCheck"};

  absl::Status StartPacketForwarder(NWUDPSession* udp_session)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void ShutdownPacketForwarder();
  void StartDatapathConnectingTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelDatapathConnectingTimerIfRunning()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status CreateNetworkPipeAndStartPacketForwarder()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void HandleDatapathConnectingTimeout();
  void StartHealthCheckTimer();
  void CancelHealthCheckTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void HandleHealthCheckTimeout();
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNDATAPATH_H_
