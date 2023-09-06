// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/ipsec/cryptor_interface.h"
#include "privacy/net/krypton/datapath/ipsec/packet_forwarder.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
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
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

// Manages the IPSec datapath on iOS.
//
// For IPSec datapath on Android, use datapath/android_ipsec/ipsec_datapath.
//
// This class is thread safe.
class IpSecDatapath : public DatapathInterface,
                      public PacketForwarder::NotificationInterface {
 public:
  // An interface for ipsec-specific extensions to the VpnService interface.
  class IpSecVpnServiceInterface : public virtual VpnServiceInterface {
   public:
    // Creates a UDP connection to an endpoint on the network.
    virtual absl::StatusOr<std::unique_ptr<PacketPipe>> CreateNetworkPipe(
        const NetworkInfo&, const Endpoint&) = 0;

    // Verifies the tunnel connection is still up.
    virtual absl::Status CheckConnection() = 0;

    // Gets the current tunnel.
    virtual PacketPipe* GetTunnel() = 0;
  };

  IpSecDatapath(const KryptonConfig& config, utils::LooperThread* looper,
                IpSecVpnServiceInterface* vpn_service,
                TimerManager* timer_manager)
      : notification_thread_(looper),
        vpn_service_(vpn_service),
        timer_manager_(timer_manager),
        periodic_health_check_enabled_(config.periodic_health_check_enabled()),
        periodic_health_check_duration_(
            absl::Seconds(config.periodic_health_check_duration().seconds())) {}
  ~IpSecDatapath() override = default;
  IpSecDatapath(const IpSecDatapath&) = delete;
  IpSecDatapath(IpSecDatapath&&) = delete;
  IpSecDatapath& operator=(const IpSecDatapath&) = delete;
  IpSecDatapath& operator=(IpSecDatapath&&) = delete;

  // Configs the datapath.
  //
  // Datapath will not run until `SwitchNetwork` is called.
  absl::Status Start(const AddEgressResponse& egress_response,
                     const TransformParams& params) override;

  // Terminates the datapath connection.
  void Stop() override;

  // Establishes the VPN tunnel.
  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             const NetworkInfo& network_info,
                             int counter) override;

  void PrepareForTunnelSwitch() override {}

  void SwitchTunnel() override {}

  // Updates crypto keys.
  absl::Status SetKeyMaterials(const TransformParams& params) override;

  void PacketForwarderFailed(const absl::Status&) override;

  void PacketForwarderPermanentFailure(const absl::Status&) override;

  void PacketForwarderConnected() override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

 private:
  absl::Mutex mutex_;
  utils::LooperThread* notification_thread_;    // Not owned by this class.
  IpSecVpnServiceInterface* vpn_service_;       // Not owned by this class.
  TimerManager* timer_manager_;                 // Not owned by this class.
  PacketPipe* tunnel_ ABSL_GUARDED_BY(mutex_);  // Not owned by this class.
  std::unique_ptr<PacketPipe> network_socket_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<CryptorInterface> encryptor_
      ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<PacketForwarder> packet_forwarder_
      ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<CryptorInterface> decryptor_
      ABSL_GUARDED_BY(mutex_);
  std::optional<uint32_t> uplink_spi_ ABSL_GUARDED_BY(mutex_);
  std::optional<TransformParams> key_material_ ABSL_GUARDED_BY(mutex_);
  std::optional<Endpoint> endpoint_ ABSL_GUARDED_BY(mutex_);
  std::optional<NetworkInfo> network_info_ ABSL_GUARDED_BY(mutex_);
  int datapath_connecting_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int health_check_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_connecting_count_ ABSL_GUARDED_BY(mutex_) = 0;
  const bool periodic_health_check_enabled_;
  const absl::Duration periodic_health_check_duration_;
  std::shared_ptr<std::atomic_bool> health_check_cancelled_
      ABSL_GUARDED_BY(mutex_);
  utils::LooperThread looper_{"HealthCheck"};

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

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_
