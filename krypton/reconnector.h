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

#ifndef PRIVACY_NET_KRYPTON_RECONNECTOR_H_
#define PRIVACY_NET_KRYPTON_RECONNECTOR_H_

#include <atomic>
#include <cstdint>
#include <optional>

#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {

class ReconnectorDebugInfo;

// Class that is responsible to keep PPN always connected. Callers can listen to
// session status by listening to |Session::NotificationInterface|.
// Thread safe.
class Reconnector : public Session::NotificationInterface {
 public:
  Reconnector(TimerManager* timer_manager, const KryptonConfig& config,
              SessionManagerInterface* session,
              TunnelManagerInterface* tunnel_manager,
              utils::LooperThread* notification_thread, KryptonClock* clock);
  ~Reconnector() override = default;

  enum State {
    kInitial,                         // InitialState
    kWaitingForSessionEstablishment,  // Session was created and waiting for
                                      // feedback from the session.
    kWaitingToReconnect,  // Trying to reconnect involving backoff algorithm.
    kConnected,           // Session is connected.
    kPermanentFailure,    // Non recoverable state and is a terminal state.
    kPaused,              // Paused by application, ex: Airplane mode.
    kSnoozed,             // Snoozed by user.
  };

  struct TelemetryData {
    void Reset() {
      control_plane_failures = 0;
      data_plane_failures = 0;
      session_restarts = 0;
    }
    int control_plane_failures = 0;
    int data_plane_failures = 0;
    int session_restarts = 0;
  };

  static constexpr int kInvalidTimerId = -1;
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  // Forces the VPN to reconnect, if it was already connected.
  void ForceReconnect() ABSL_LOCKS_EXCLUDED(mutex_);

  void RegisterNotificationInterface(
      KryptonNotificationInterface* notification_interface);

  absl::Status Snooze(absl::Duration duration) ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status Resume() ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status ExtendSnooze(absl::Duration extend_duration)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void CollectTelemetry(KryptonTelemetry* telemetry)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void ControlPlaneConnected() ABSL_LOCKS_EXCLUDED(mutex_) override;

  void DatapathConnected() ABSL_LOCKS_EXCLUDED(mutex_) override;
  void DatapathDisconnected(const NetworkInfo& network,
                            const absl::Status& reason)
      ABSL_LOCKS_EXCLUDED(mutex_) override;

  void ControlPlaneDisconnected(const absl::Status& reason)
      ABSL_LOCKS_EXCLUDED(mutex_) override;
  void PermanentFailure(const absl::Status& disconnect_status)
      ABSL_LOCKS_EXCLUDED(mutex_) override;

  State state() const {
    absl::MutexLock l(&mutex_);
    return state_;
  }

  // Set network. This could happen when the session is connecting
  // or connected or this is used to wake up the connection.
  // nullopt indicates that are no existing network to send tunnel data.
  absl::Status SetNetwork(std::optional<NetworkInfo> network_info)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void SetSimulatedNetworkFailure(bool simulated_network_failure);

  void GetDebugInfo(ReconnectorDebugInfo* debug_info)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Test only parameters
  int SuccessiveDatapathFailuresTestOnly() const {
    absl::MutexLock l(&mutex_);
    return successive_datapath_failures_;
  }

  int SuccessiveControlplaneFailuresTestOnly() const {
    absl::MutexLock l(&mutex_);
    return successive_control_plane_failures_;
  }

  int DatapathWatchdogTimerIdTestOnly() const {
    absl::MutexLock l(&mutex_);
    return datapath_watchdog_timer_id_;
  }

 private:
  void SetState(State state) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void StartReconnection() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Duration GetReconnectDuration() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void ResetFailureCounters() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Timer Expires
  void ReconnectTimerExpired() ABSL_LOCKS_EXCLUDED(mutex_);
  void SessionConnectionTimerExpired() ABSL_LOCKS_EXCLUDED(mutex_);
  void DatapathWatchdogTimerExpired() ABSL_LOCKS_EXCLUDED(mutex_);
  void SnoozeTimerExpired() ABSL_LOCKS_EXCLUDED(mutex_);

  // Reconnection Timer.
  absl::Status StartReconnectorTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status StartSnoozeTimer(absl::Duration duration)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelReconnectorTimerIfRunning() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelSnoozeTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Connection deadline timer
  absl::Status StartConnectionDeadlineTimer()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelConnectionDeadlineTimerIfRunning()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Datapath watchdog timer
  absl::Status StartDatapathWatchdogTimer()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelDatapathWatchdogTimerIfRunning()

      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void CancelAllTimersIfRunning() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  DisconnectionStatus GetDisconnectionStatus(const absl::Status& reason)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void EstablishSession() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void TerminateSession(const absl::Status& reason, bool forceFailOpen)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  TimerManager* timer_manager_;                 // Not owned.
  KryptonNotificationInterface* notification_;  // Not owned.
  SessionManagerInterface* session_manager_;    // Not owned.
  TunnelManagerInterface* tunnel_manager_;      // Not owned.
  const KryptonConfig config_;
  utils::LooperThread* notification_thread_;
  KryptonClock* clock_;

  mutable absl::Mutex mutex_;
  State state_ ABSL_GUARDED_BY(mutex_);
  std::atomic_int session_restart_counter_ = 0;
  int reconnector_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int connection_deadline_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int datapath_watchdog_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  int snooze_timer_id_ ABSL_GUARDED_BY(mutex_) = -1;
  std::optional<NetworkInfo> active_network_info_ ABSL_GUARDED_BY(mutex_);
  // Used to determine whether active_network == nullopt is intentional, or
  // merely a default value.
  std::atomic_bool set_network_called_ = false;
  // Represents the successive datapath failures after control plane is
  // connected.
  uint32_t successive_datapath_failures_ ABSL_GUARDED_BY(mutex_) = 0;
  uint32_t successive_control_plane_failures_ ABSL_GUARDED_BY(mutex_) = 0;
  TelemetryData telemetry_data_;
  absl::Time snooze_end_time_;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_RECONNECTOR_H_
