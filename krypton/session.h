// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_SESSION_H_
#define PRIVACY_NET_KRYPTON_SESSION_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/common/proto/update_path_info.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/datapath_address_selector.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/provision.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

class SessionDebugInfo;

std::string ProtoToJsonString(
    const ppn::UpdatePathInfoRequest& update_path_info_request);

// Session or Krypton session that represents a session to the copper
// server. This also is the state machine for establishing the Copper |
// Egress server. Thread safe implementation.
class Session : public DatapathInterface::NotificationInterface,
                public Provision::NotificationInterface {
 public:
  // Notification for Session state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Lifecycle events.
    // Control plane starting attempt to negotiate setting up a tunnel.
    virtual void ControlPlaneConnecting() = 0;
    // Control plane has successfully negotiated setting up the tunnel. This
    // event doesn't signify that the datapath is connected.
    virtual void ControlPlaneConnected() = 0;
    // Control plane is broken and implicitly implies that there is no data
    // plane either.
    virtual void ControlPlaneDisconnected(const absl::Status& status) = 0;
    // Session has non recoverable error and the Krypton layer needs to be torn
    // down.
    virtual void PermanentFailure(const absl::Status& status) = 0;

    // Datapath events
    // Attempting to connect datapath.
    virtual void DatapathConnecting() = 0;
    // Datapath has been established and the tunnel is up for user traffic.
    virtual void DatapathConnected() = 0;
    // Datapath is disconnected and the user traffic is not flowing through the
    // tunnel. Control plane is still up.
    virtual void DatapathDisconnected(const NetworkInfo& network,
                                      const absl::Status& status) = 0;
  };

  Session(const KryptonConfig& config, std::unique_ptr<Auth> auth,
          std::unique_ptr<EgressManager> egress_manager,
          std::unique_ptr<DatapathInterface> datapath,
          VpnServiceInterface* vpn_service, TimerManager* timer_manager,
          HttpFetcherInterface* http_fetcher,
          TunnelManagerInterface* tunnel_manager,
          std::optional<NetworkInfo> network_info,
          utils::LooperThread* notification_thread);

  ~Session() override;

  enum class State {
    kInitialized,
    kEgressSessionCreated,
    kControlPlaneConnected,
    kDataPlaneConnected,
    kStopped,
    kDataPlaneError,
    kDataPlanePermanentError,
    kSessionError,    // Common catch all.
    kPermanentError,  // Permanent error. Krypton needs to stop.
  };

  // Register for status change notifications.
  void RegisterNotificationHandler(NotificationInterface* notification) {
    notification_ = notification;
  }

  // Starts a session.
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  // Stops a session.
  void Stop(bool forceFailOpen) ABSL_LOCKS_EXCLUDED(mutex_);

  void ForceTunnelUpdate() ABSL_LOCKS_EXCLUDED(mutex_);

  // Override methods from the interface.
  void DatapathEstablished() override ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathFailed(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathPermanentFailure(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DoRekey() override ABSL_LOCKS_EXCLUDED(mutex_);
  void DoUplinkMtuUpdate(int uplink_mtu, int tunnel_mtu) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DoDownlinkMtuUpdate(int downlink_mtu) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void Provisioned(const AddEgressResponse& egress_response,
                   bool is_rekey) override ABSL_LOCKS_EXCLUDED(mutex_);
  void ProvisioningFailure(absl::Status status, bool permanent) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Switch network.
  absl::Status SetNetwork(const NetworkInfo& network_info)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void CollectTelemetry(KryptonTelemetry* telemetry)
      ABSL_LOCKS_EXCLUDED(mutex_);
  void GetDebugInfo(KryptonDebugInfo* debug_info) ABSL_LOCKS_EXCLUDED(mutex_);
  // Callback from DatapathReattempt timer.
  void AttemptDatapathReconnect() ABSL_LOCKS_EXCLUDED(mutex_);

  // Callback from DatapathConnecting timer.
  void HandleDatapathConnectingTimeout() ABSL_LOCKS_EXCLUDED(mutex_);

  // Test only methods
  absl::Status LatestStatusTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return latest_status_;
  }

  int DatapathReattemptCountTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return datapath_reattempt_count_;
  }

  int DatapathReattemptTimerIdTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return datapath_reattempt_timer_id_;
  }

  int GetUplinkMtuTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return uplink_mtu_;
  }

  int GetDownlinkMtuTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return downlink_mtu_;
  }

  int GetTunnelMtuTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return tunnel_mtu_;
  }

  State GetStateTestOnly() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return state_;
  }

  std::optional<NetworkInfo> GetActiveNetworkInfoTestOnly() const
      ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return active_network_info_;
  }

 private:
  // Callback methods from timers.
  void HandleRekeyTimerExpiry() ABSL_LOCKS_EXCLUDED(mutex_);

  void SetState(State state, absl::Status status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Status ConnectDatapath(const NetworkInfo& network_info)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status BuildTunFdData(TunFdData* tun_fd_data) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartRekeyTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void StartDatapathReattemptTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void StartDatapathConnectingTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Status CreateTunnel(bool force_tunnel_update)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Attempts to update an existing tunnel with new parameters.
  void UpdateTunnelIfNeeded(bool force_tunnel_update)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Status CreateTunnelIfNeeded() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Returns true if the given status indicates that a status returned from
  // CreateTunnel should be considered "permanent".
  bool IsTunnelCreationErrorPermanent(const absl::Status& status);

  void ResetAllDatapathReattempts() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void Rekey() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void RekeyDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelRekeyTimerIfRunning() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelDatapathReattemptTimerIfRunning()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelDatapathConnectingTimerIfRunning()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Status SendUpdatePathInfoRequest()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void HandleUpdatePathInfoResponse(const HttpResponse& http_response)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void HandleDatapathFailure(const absl::Status& status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void NotifyDatapathDisconnected(const NetworkInfo& network_info,
                                  const absl::Status& status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void NotifyDatapathConnecting() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void NotifyControlPlaneConnecting() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  mutable absl::Mutex mutex_;

  KryptonConfig config_;

  std::unique_ptr<DatapathInterface> datapath_;

  bool datapath_connecting_timer_enabled_ ABSL_GUARDED_BY(mutex_);
  absl::Duration datapath_connecting_timer_duration_ ABSL_GUARDED_BY(mutex_);
  absl::Duration rekey_timer_duration_ ABSL_GUARDED_BY(mutex_);
  int rekey_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_reattempt_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_connecting_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;

  NotificationInterface* notification_;       // Not owned.
  VpnServiceInterface* vpn_service_;          // Not owned.
  TimerManager* timer_manager_;               // Not owned.
  utils::LooperThread* notification_thread_;  // Not owned.
  TunnelManagerInterface* tunnel_manager_;    // Not owned.

  DatapathAddressSelector datapath_address_selector_;
  std::optional<AddEgressResponse> add_egress_response_ ABSL_GUARDED_BY(mutex_);
  uint32_t uplink_spi_ ABSL_GUARDED_BY(mutex_);
  std::vector<std::string> egress_node_sock_addresses_ ABSL_GUARDED_BY(mutex_);
  std::vector<ppn::IpRange> user_private_ip_ ABSL_GUARDED_BY(mutex_);

  State state_ ABSL_GUARDED_BY(mutex_) = State::kInitialized;
  absl::Status latest_status_ ABSL_GUARDED_BY(mutex_) = absl::OkStatus();
  absl::Status latest_datapath_status_ ABSL_GUARDED_BY(mutex_) =
      absl::OkStatus();

  std::optional<NetworkInfo> active_network_info_ ABSL_GUARDED_BY(mutex_);

  // Counter for the number of times SwitchNetwork has been called for this
  // session.
  int datapath_switch_network_counter_ ABSL_GUARDED_BY(mutex_) = 0;

  // Counts the number of times the endpoint switched till now.
  int datapath_reattempt_count_ ABSL_GUARDED_BY(mutex_) = 0;
  uint32_t network_switches_count_ ABSL_GUARDED_BY(mutex_) = 0;
  uint32_t successful_network_switches_ ABSL_GUARDED_BY(mutex_) = 0;
  absl::Time network_switch_start_time_ ABSL_GUARDED_BY(mutex_) =
      absl::InfinitePast();
  std::vector<google::protobuf::Duration> network_switch_latencies_
      ABSL_GUARDED_BY(mutex_);

  // Initialize uplink and downlink MTU values to 0 so that the initial update
  // will always cause the value to change.
  int uplink_mtu_ ABSL_GUARDED_BY(mutex_) = 0;
  int downlink_mtu_ ABSL_GUARDED_BY(mutex_) = 0;
  // Value of MTU for the TUN interface when dynamic MTU is enabled. Initialized
  // to a commonly used MTU value of 1500, minus some overhead.
  int tunnel_mtu_ ABSL_GUARDED_BY(mutex_) = 1395;

  bool datapath_connected_ ABSL_GUARDED_BY(mutex_) = false;
  // Tells whether a network switch is currently in progress.
  bool switching_network_ ABSL_GUARDED_BY(mutex_) = false;
  int number_of_rekeys_ ABSL_GUARDED_BY(mutex_) = 0;

  utils::LooperThread looper_;
  std::unique_ptr<Provision> provision_ ABSL_GUARDED_BY(mutex_);
  HttpFetcher http_fetcher_;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_SESSION_H_
