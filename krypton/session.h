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

#ifndef PRIVACY_NET_KRYPTON_SESSION_H_
#define PRIVACY_NET_KRYPTON_SESSION_H_

#include <atomic>
#include <memory>
#include <optional>

#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/call_once.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

class SessionDebugInfo;

// Session or Krypton session that represents a session to the copper
// server. This also is the statemachine for establishing the Copper |
// Egress server. Thread safe implementation.
class Session : public Auth::NotificationInterface,
                EgressManager::NotificationInterface,
                DatapathInterface::NotificationInterface {
 public:
  // Notification for Session state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Lifecycle events.
    // Control plane Zinc+Brass have successfully negotiated in setting up the
    // tunnel.  This event doesn't signify that the datapath is connected.
    virtual void ControlPlaneConnected() = 0;
    // Status update on the connection.
    virtual void StatusUpdated() = 0;
    // Control plane is broken and implicitly implies that there is no data
    // plane either.
    virtual void ControlPlaneDisconnected(const absl::Status& status) = 0;
    // Session has non recoverable error and the Krypton layer needs to be torn
    // down.
    virtual void PermanentFailure(const absl::Status& status) = 0;

    // Datapath events
    // Datapath has been established and the tunnel is up for user traffic.
    virtual void DatapathConnected() = 0;
    // Datapath is disconnected and the user traffic is not flowing through the
    // tunnel.  Control plane is still up.
    virtual void DatapathDisconnected(const NetworkInfo& network,
                                      const absl::Status& status) = 0;
  };

  Session(Auth* auth, EgressManager* egress_manager,
          DatapathInterface* datapath, VpnServiceInterface* vpn_service,
          TimerManager* timer_manager, absl::optional<NetworkInfo> network_info,
          KryptonConfig* config, utils::LooperThread* notification_thread);

  ~Session() override;

  enum class State {
    kInitialized,
    kAuthSuccessful,
    kEgressSessionCreated,
    kConnected,  // This indicates auth, egress and datapath were successful.
    kSessionError,         // Common catch all.
    kPermanentError,       // Permanent error. Krypton needs to stop.
  };

  // Register for status change notifications.
  void RegisterNotificationHandler(NotificationInterface* notification) {
    notification_ = notification;
  }

  // Starts a session.
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  // Stops a session.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  // Override methods from the interface.
  void AuthSuccessful(bool is_rekey) override ABSL_LOCKS_EXCLUDED(mutex_);
  void AuthFailure(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void EgressAvailable(bool is_rekey) override ABSL_LOCKS_EXCLUDED(mutex_);
  void EgressUnavailable(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathEstablished() override ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathFailed(const absl::Status& status, int failed_fd) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathPermanentFailure(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  void DoRekey() override ABSL_LOCKS_EXCLUDED(mutex_);

  State state() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return state_;
  }

  absl::Status latest_status() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return latest_status_;
  }

  absl::Status latest_datapath_status() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return latest_datapath_status_;
  }

  // Switch network.
  absl::Status SetNetwork(absl::optional<NetworkInfo> network_info)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // returns nullopt on no networks.
  absl::optional<NetworkInfo> active_network_info() const
      ABSL_LOCKS_EXCLUDED(mutex_);

  void CollectTelemetry(KryptonTelemetry* telemetry)
      ABSL_LOCKS_EXCLUDED(mutex_);
  void GetDebugInfo(SessionDebugInfo* debug_info) ABSL_LOCKS_EXCLUDED(mutex_);
  // Callback from DatapathReattempt timer.
  void AttemptDatapathReconnect() ABSL_LOCKS_EXCLUDED(mutex_);

  // Test only methods
  int DatapathReattemptCountTestOnly() ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return datapath_reattempt_count_.load();
  }
  int DatapathReattemptTimerIdTestOnly() ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return datapath_reattempt_timer_id_;
  }

  crypto::SessionCrypto* MutableCryptoTestOnly() ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return key_material_.get();
  }
  absl::Status RekeyTestOnly() ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return Rekey();
  }
  absl::optional<int> active_tun_fd_test_only() const
      ABSL_LOCKS_EXCLUDED(mutex_);
  absl::optional<int> previous_tun_fd_test_only() const
      ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  // Callback methods from timers.
  void FetchCounters() ABSL_LOCKS_EXCLUDED(mutex_);

  void SetState(State state) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void UpdateLatestStatus(const absl::Status& status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void UpdateLatestDatapathStatus(const absl::Status& status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void UpdateActiveNetworkInfo(absl::optional<NetworkInfo> network_info)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status SwitchDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status BuildTunFdData(TunFdData* tun_fd_data) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartFetchCountersTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void StartDatapathReattemptTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Status CreateTunnelIfNeeded() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status ClearDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void ResetAllDatapathReattempts() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  bool IsFdCurrentActiveFd(int failed_fd) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status SetRemoteKeyMaterial() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void PpnDataplaneRequest(bool rekey = false)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status Rekey() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void RekeyDatapath() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelFetcherTimerIfRunning() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelDatapathReattemptTimerIfRunning()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::StatusOr<std::string> SelectDatapathAddress();

  mutable absl::Mutex mutex_;
  Auth* auth_;                                // Not owned.
  EgressManager* egress_manager_;             // Not owned.
  NotificationInterface* notification_;       // Not owned.
  DatapathInterface* datapath_;               // Not owned.
  VpnServiceInterface* vpn_service_;          // Not owned.
  TimerManager* timer_manager_;               // Not owned.
  KryptonConfig* config_;                     // Not owned.
  utils::LooperThread* notification_thread_;  // Not owned.

  State state_ ABSL_GUARDED_BY(mutex_) = State::kInitialized;
  absl::Status latest_status_ ABSL_GUARDED_BY(mutex_) = absl::OkStatus();
  absl::Status latest_datapath_status_ ABSL_GUARDED_BY(mutex_) =
      absl::OkStatus();

  // Currently active tunnel.
  std::unique_ptr<PacketPipe> active_tunnel_ ABSL_GUARDED_BY(mutex_);
  // Previously active tunnel.
  std::unique_ptr<PacketPipe> previous_tunnel_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<PacketPipe> active_network_socket_ ABSL_GUARDED_BY(mutex_);
  absl::optional<NetworkInfo> active_network_info_ ABSL_GUARDED_BY(mutex_);

  // Counts the number of times the endpoint switched till now.
  // TODO: Should this be plumbed from Xenon.
  std::atomic_int network_switches_count_ ABSL_GUARDED_BY(mutex_) = 1;
  int fetch_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_reattempt_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  std::atomic_int datapath_reattempt_count_ ABSL_GUARDED_BY(mutex_) = 0;

  std::unique_ptr<crypto::SessionCrypto> key_material_ ABSL_GUARDED_BY(mutex_);
  absl::optional<std::string> rekey_verification_key_ ABSL_GUARDED_BY(mutex_);
  std::atomic_bool datapath_connected_ ABSL_GUARDED_BY(mutex_) = false;
  std::string copper_address_ ABSL_GUARDED_BY(mutex_);
  absl::Time last_rekey_time_ ABSL_GUARDED_BY(mutex_);
  // Keep track of the last reported network switches.
  std::atomic_int last_repoted_network_switches_ = 0;
  std::atomic_int number_of_rekeys_ = 0;
  std::atomic_int datapath_ipv4_attempts_ = 0;
  std::atomic_int datapath_ipv6_attempts_ = 0;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_SESSION_H_
