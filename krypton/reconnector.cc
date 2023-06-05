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

#include "privacy/net/krypton/reconnector.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

// Limit the max duration of reattempt to once a day.
constexpr absl::Duration kMaxDuration = absl::Hours(24);

std::string StateString(Reconnector::State state) {
  switch (state) {
    case Reconnector::State::kInitial:
      return "Initial";
    case Reconnector::State::kWaitingToReconnect:
      return "WaitingToReconnect";
    case Reconnector::State::kPermanentFailure:
      return "PermanentFailure";
    case Reconnector::State::kWaitingForSessionEstablishment:
      return "WaitingForSessionEstablishment";
    case Reconnector::State::kConnected:
      return "Connected";
    case Reconnector::State::kPaused:
      return "Paused";
    case Reconnector::State::kSnoozed:
      return "Snoozed";
  }
}
}  // namespace

Reconnector::Reconnector(TimerManager* timer_manager,
                         const KryptonConfig& config,
                         SessionManagerInterface* session_manager,
                         TunnelManagerInterface* tunnel_manager,
                         utils::LooperThread* notification_thread,
                         KryptonClock* clock)
    : timer_manager_(timer_manager),
      session_manager_(session_manager),
      tunnel_manager_(tunnel_manager),
      config_(config),
      notification_thread_(notification_thread),
      clock_(clock),
      state_(kInitial) {
  session_manager_->RegisterNotificationInterface(this);
}

void Reconnector::Start() {
  absl::MutexLock l(&mutex_);
  DCHECK(notification_);
  EstablishSession();
}

void Reconnector::Stop() {
  absl::MutexLock l(&mutex_);
  TerminateSession(absl::OkStatus(), /*forceFailOpen=*/false);
  CancelAllTimersIfRunning();
}

void Reconnector::CancelAllTimersIfRunning() {
  CancelConnectionDeadlineTimerIfRunning();
  CancelReconnectorTimerIfRunning();
  CancelDatapathWatchdogTimerIfRunning();
  CancelSnoozeTimer();
}

void Reconnector::RegisterNotificationInterface(
    KryptonNotificationInterface* notification_interface) {
  notification_ = notification_interface;
}

void Reconnector::ControlPlaneConnected() {
  LOG(INFO) << "Session control plane connected.";
  if (notification_ != nullptr) {
    auto notification = notification_;
    notification_thread_->Post([notification] {
      // TODO: There is still a possibility that we might get
      // Connected, Disconnected and may result in a flood to the backend.
      // Introduce backoff if there were continuous connection/disconnection
      // events
      notification->ControlPlaneConnected();
    });
  }
  absl::MutexLock l(&mutex_);
  // There is a race condition of deadline timer expired and connected events
  // are called simulateneously and ConnectionDeadlineTimerExpiry won the race.
  if (connection_deadline_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Connection moving to connected state after timer expiry, "
                 "Procedures of deadline timers are being run";
    return;
  }

  // Check that statemachine is in the right state.
  DCHECK(state_ == kWaitingForSessionEstablishment);
  // Ensure that there is no reconnection timer running.
  DCHECK(reconnector_timer_id_ == kInvalidTimerId);

  successive_control_plane_failures_ = 0;

  CancelConnectionDeadlineTimerIfRunning();

  SetState(kConnected);
}

// Session is disconnected.
void Reconnector::ControlPlaneDisconnected(const absl::Status& reason) {
  LOG(INFO) << "Session control plane disconnected.";
  absl::MutexLock l(&mutex_);
  // There is a race condition of deadline timer expired and disconnected
  // events are called simulateneously and ConnectionDeadlineTimerExpiry won
  // the race. Also, the session could be moving from Connected to
  // Disconnected and there might be not be any timer running.
  if (connection_deadline_timer_id_ == kInvalidTimerId &&
      state_ != kConnected) {
    LOG(INFO) << "Disconnected event received in a wrong state or deadline "
                 "timer has already expired";
    return;
  }

  CancelConnectionDeadlineTimerIfRunning();

  if (notification_ != nullptr) {
    auto notification = notification_;
    auto disconnection_status = GetDisconnectionStatus(reason);
    notification_thread_->Post([notification, disconnection_status] {
      notification->Disconnected(disconnection_status);
    });
  }
  successive_control_plane_failures_ += 1;
  ++telemetry_data_.control_plane_failures;
  StartReconnection();
}

void Reconnector::ForceReconnect() {
  absl::MutexLock l(&mutex_);
  if (state_ != kConnected) {
    LOG(INFO) << "Not forcing reconnect, because datapath is not connected.";
    return;
  }
  LOG(INFO) << "Forcing reconnection.";
  TerminateSession(absl::OkStatus(), /*forceFailOpen=*/false);

  SetState(kWaitingToReconnect);
  auto notification = notification_;
  ReconnectionStatus status;
  if (set_network_called_) {
    status.set_has_available_networks(active_network_info_.has_value());
  }
  status.set_is_blocking_traffic(tunnel_manager_->IsTunnelActive());
  status.mutable_time_to_reconnect()->set_seconds(0);
  status.mutable_time_to_reconnect()->set_nanos(0);
  notification_thread_->Post(
      [notification, status] { notification->WaitingToReconnect(status); });

  EstablishSession();
}

void Reconnector::StartReconnection() {
  TerminateSession(absl::DeadlineExceededError("Waiting to reconnect"),
                   /*forceFailOpen=*/false);
  PPN_LOG_IF_ERROR(StartReconnectorTimer());
  SetState(kWaitingToReconnect);
}

// Session had a non recoverable error.
void Reconnector::PermanentFailure(const absl::Status& disconnect_status) {
  LOG(INFO) << "Session has Permanent failure.";
  absl::MutexLock l(&mutex_);
  CancelAllTimersIfRunning();

  TerminateSession(disconnect_status, /*forceFailOpen=*/false);
  SetState(kPermanentFailure);

  auto notification = notification_;
  notification_thread_->Post([notification, disconnect_status] {
    notification->PermanentFailure(disconnect_status);
  });
}

void Reconnector::EstablishSession() {
  session_manager_->EstablishSession(session_restart_counter_.fetch_add(1),
                                     tunnel_manager_, active_network_info_);
  ++telemetry_data_.session_restarts;
  // Start the Connection deadline timer to ensure the session moves to
  // connected within the time.
  PPN_LOG_IF_ERROR(StartConnectionDeadlineTimer());
  SetState(kWaitingForSessionEstablishment);
  // Send a Connecting notification to the PPN library.
  auto notification = notification_;
  ConnectingStatus status;
  status.set_is_blocking_traffic(tunnel_manager_->IsTunnelActive());
  notification_thread_->Post(
      [notification, status] { notification->Connecting(status); });
}

void Reconnector::TerminateSession(const absl::Status& reason,
                                   bool forceFailOpen) {
  session_manager_->TerminateSession(forceFailOpen);
  // Send a Disconnected notification to the PPN library.
  auto notification = notification_;
  auto disconnection_status = GetDisconnectionStatus(reason);
  notification_thread_->Post([notification, disconnection_status] {
    notification->Disconnected(disconnection_status);
  });
}

void Reconnector::ReconnectTimerExpired() {
  LOG(INFO) << "Reconnect timer expired.";
  absl::MutexLock l(&mutex_);
  DCHECK(state_ == kWaitingToReconnect);
  DCHECK(connection_deadline_timer_id_ == kInvalidTimerId);

  if (state_ != kWaitingToReconnect) {
    LOG(ERROR) << "Reconnect timer expired but in incorrect state."
               << StateString(state_);
    return;
  }
  reconnector_timer_id_ = kInvalidTimerId;
  EstablishSession();
}

void Reconnector::SessionConnectionTimerExpired() {
  absl::MutexLock l(&mutex_);
  // There is a race where session events could be received at the same time as
  // this timer expiry. if the session events won, just return.
  if (connection_deadline_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Connection deadline timer is already cancelled";
    return;
  }
  LOG(INFO) << "Session Connection deadline expired";
  // if we are not in kWaitingForSessionEstablishment, then set the
  // connection_deadline_timer_id = kInvalidTimerId;
  DCHECK(state_ == kWaitingForSessionEstablishment);
  // Clean up the session.
  DCHECK(reconnector_timer_id_ == kInvalidTimerId);
  connection_deadline_timer_id_ = kInvalidTimerId;
  successive_control_plane_failures_ += 1;
  ++telemetry_data_.control_plane_failures;
  StartReconnection();
}

void Reconnector::SnoozeTimerExpired() {
  auto status = Resume();
  if (!status.ok()) {
    LOG(ERROR) << "Failed to resume PPN after snooze: " << status;
  }
}

absl::Duration Reconnector::GetReconnectDuration() {
  auto max_reattempts_till_now = std::max(successive_control_plane_failures_,
                                          successive_datapath_failures_);

  absl::Duration reconnector_duration = absl::Milliseconds(
      config_.reconnector_config().initial_time_to_reconnect_msec());

  reconnector_duration *=
      std::pow(2, static_cast<double>(max_reattempts_till_now));

  LOG(INFO) << "Control plane reconnection failures "
            << successive_control_plane_failures_
            << " Dataplane reconnection failures "
            << successive_datapath_failures_ << " Reconnection duration "
            << reconnector_duration;

  // Limit the reconnect duration to once a day.
  return std::min(reconnector_duration, kMaxDuration);
}

void Reconnector::ResetFailureCounters() {
  LOG(INFO) << "Resetting failure counters";
  successive_control_plane_failures_ = 0;
  successive_datapath_failures_ = 0;
}

absl::Status Reconnector::StartReconnectorTimer() {
  auto duration = GetReconnectDuration();

  CancelReconnectorTimerIfRunning();
  LOG(INFO) << "Starting reconnect timer.";
  PPN_ASSIGN_OR_RETURN(
      reconnector_timer_id_,
      timer_manager_->StartTimer(
          duration, absl::bind_front(&Reconnector::ReconnectTimerExpired, this),
          "Reconnect"));

  // Create and put a Reconnecting notification on the Looper.
  ReconnectionStatus status;
  if (set_network_called_) {
    status.set_has_available_networks(active_network_info_.has_value());
  }
  status.set_is_blocking_traffic(tunnel_manager_->IsTunnelActive());
  PPN_RETURN_IF_ERROR(
      utils::ToProtoDuration(duration, status.mutable_time_to_reconnect()));

  auto notification = notification_;
  notification_thread_->Post(
      [notification, status] { notification->WaitingToReconnect(status); });

  return absl::OkStatus();
}

absl::Status Reconnector::StartSnoozeTimer(absl::Duration duration) {
  // We want to let the currently snoozed process run its course instead of
  // restarting it.
  if (snooze_timer_id_ != kInvalidTimerId) {
    return absl::AlreadyExistsError(
        "Snooze is already scheduled. Refusing to reschedule.");
  }

  if (state_ == kPermanentFailure) {
    return absl::FailedPreconditionError(
        "Krypton is in a " + StateString(state_) + ". Refusing to snooze.");
  }
  PPN_ASSIGN_OR_RETURN(
      snooze_timer_id_,
      timer_manager_->StartTimer(
          duration, absl::bind_front(&Reconnector::SnoozeTimerExpired, this),
          "Snooze"));

  return absl::OkStatus();
}

void Reconnector::CancelReconnectorTimerIfRunning() {
  if (reconnector_timer_id_ == kInvalidTimerId) {
    return;
  }

  timer_manager_->CancelTimer(reconnector_timer_id_);
  reconnector_timer_id_ = kInvalidTimerId;
}

void Reconnector::CancelSnoozeTimer() {
  if (snooze_timer_id_ == kInvalidTimerId) {
    return;
  }

  timer_manager_->CancelTimer(snooze_timer_id_);
  snooze_timer_id_ = kInvalidTimerId;
}

absl::Status Reconnector::StartConnectionDeadlineTimer() {
  absl::Duration duration = absl::Milliseconds(
      config_.reconnector_config().session_connection_deadline_msec());
  LOG(INFO) << "Starting connection timer.";
  // Cancel any session connection timers if running.
  CancelConnectionDeadlineTimerIfRunning();
  PPN_ASSIGN_OR_RETURN(
      connection_deadline_timer_id_,
      timer_manager_->StartTimer(
          duration,
          absl::bind_front(&Reconnector::SessionConnectionTimerExpired, this),
          "SessionConnection"));

  return absl::OkStatus();
}

void Reconnector::CancelConnectionDeadlineTimerIfRunning() {
  if (connection_deadline_timer_id_ == kInvalidTimerId) {
    return;
  }

  timer_manager_->CancelTimer(connection_deadline_timer_id_);
  connection_deadline_timer_id_ = kInvalidTimerId;
}

void Reconnector::DatapathWatchdogTimerExpired() {
  absl::MutexLock l(&mutex_);
  if (datapath_watchdog_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Datapath timer already expired";
    return;
  }
  LOG(INFO) << "Datapath watchdog expired";
  DCHECK(state_ == kConnected);
  datapath_watchdog_timer_id_ = kInvalidTimerId;
  // Start the reconnection.
  StartReconnection();
}

absl::Status Reconnector::StartDatapathWatchdogTimer() {
  absl::Duration duration = absl::Milliseconds(
      config_.reconnector_config().datapath_watchdog_timer_msec());
  LOG(INFO) << "Starting datapath watchdog timer.";
  // There could be multiple back to back notifications from the datapath due to
  // session reattempts.  Cancel any timer if running.
  CancelDatapathWatchdogTimerIfRunning();
  PPN_ASSIGN_OR_RETURN(
      datapath_watchdog_timer_id_,
      timer_manager_->StartTimer(
          duration,
          absl::bind_front(&Reconnector::DatapathWatchdogTimerExpired, this),
          "DatapathWatchdog"));

  return absl::OkStatus();
}

void Reconnector::CancelDatapathWatchdogTimerIfRunning() {
  if (datapath_watchdog_timer_id_ == kInvalidTimerId) {
    return;
  }

  timer_manager_->CancelTimer(datapath_watchdog_timer_id_);
  datapath_watchdog_timer_id_ = kInvalidTimerId;
}

void Reconnector::SetState(Reconnector::State state) {
  LOG(INFO) << "Transitioning from " << StateString(state_) << " to "
            << StateString(state);
  state_ = state;
}

void Reconnector::DatapathConnected() {
  LOG(INFO) << "Datapath connected.";
  // This has no impact on the reconnection logic and the status is propagated
  // to UX layer as Connected.
  auto notification = notification_;
  // TODO: The status reported from here is currently ignored, and we
  // don't have all the data to populate it. So leave it empty for now.
  ConnectionStatus status;
  notification_thread_->Post(
      [notification, status] { notification->Connected(status); });
  // Cancel any datapath watchdog timer and reset the counts.
  absl::MutexLock l(&mutex_);
  successive_datapath_failures_ = 0;
  CancelDatapathWatchdogTimerIfRunning();
}

void Reconnector::DatapathDisconnected(const NetworkInfo& network,
                                       const absl::Status& reason) {
  LOG(INFO) << "Datapath disconnected.";
  auto notification = notification_;

  // This has no impact on the reconnection logic and the reason is propagated
  // to UX layer as Disconnected;
  notification_thread_->Post([notification, network, reason] {
    notification->NetworkDisconnected(network, reason);
  });

  // Also notify the user that the PPN is disconnected.
  absl::MutexLock l(&mutex_);
  auto disconnection_status = GetDisconnectionStatus(reason);
  notification_thread_->Post([notification, disconnection_status] {
    notification->Disconnected(disconnection_status);
  });
  successive_datapath_failures_ += 1;
  ++telemetry_data_.data_plane_failures;
  PPN_LOG_IF_ERROR(StartDatapathWatchdogTimer());
}

absl::Status Reconnector::Snooze(absl::Duration duration) {
  absl::MutexLock l(&mutex_);
  if (state_ == kPermanentFailure) {
    return absl::FailedPreconditionError(
        "Krypton is in state " + StateString(state_) + ". Refusing to snooze.");
  }
  // If no session is created, session_manager_->TerminateSession() does a
  // LOG(ERROR) and returns (i.e. a no-op).
  TerminateSession(absl::OkStatus(), /*forceFailOpen=*/true);
  auto notification = notification_;
  CancelAllTimersIfRunning();
  SetState(kSnoozed);
  SnoozeStatus status;
  snooze_end_time_ = clock_->Now() + duration;
  PPN_RETURN_IF_ERROR(
      utils::ToProtoTime(snooze_end_time_, status.mutable_snooze_end_time()));
  notification_thread_->Post(
      [notification, status] { notification->Snoozed(status); });
  return StartSnoozeTimer(duration);
}

absl::Status Reconnector::Resume() {
  absl::MutexLock l(&mutex_);
  // In a scenario where we did not have a network when, resuming (e.g. Airplane
  // mode) and after resuming we do have a network, the device would be able to
  // connect to the internet unprotected until a reconnection attempt (which
  // could take a significant amount of time). Thus, here we create a temporary
  // tunnel to block the traffic until EstablishSession() completes.
  if (!tunnel_manager_->RecreateTunnelIfNeeded().ok()) {
    LOG(ERROR)
        << "Failed to recreate tunnel to block traffic for safe disconnect.";
  }
  auto notification = notification_;
  CancelSnoozeTimer();
  if (state_ != kSnoozed) {
    return absl::FailedPreconditionError(
        "Cannot resume PPN because it is not snoozed.");
  }

  ResumeStatus status;
  status.set_has_available_networks(active_network_info_.has_value());
  status.set_is_blocking_traffic(tunnel_manager_->IsTunnelActive());
  notification_thread_->Post(
      [notification, status] { notification->Resumed(status); });
  EstablishSession();
  return absl::OkStatus();
}

absl::Status Reconnector::ExtendSnooze(absl::Duration extend_duration) {
  absl::MutexLock l(&mutex_);
  if (state_ != kSnoozed) {
    return absl::FailedPreconditionError(
        "Unable to extend snooze duration since Krypton is not Snoozed.");
  }
  absl::Time proposed_snooze_end_time = snooze_end_time_ + extend_duration;
  absl::Time time_now = clock_->Now();
  if (proposed_snooze_end_time < time_now) {  // This should never happen.
    return absl::FailedPreconditionError(
        "New snooze duration would already be expired.");
  }
  absl::Duration new_snooze_duration = proposed_snooze_end_time - time_now;
  snooze_end_time_ = proposed_snooze_end_time;
  CancelSnoozeTimer();
  auto notification = notification_;
  SnoozeStatus status;
  PPN_RETURN_IF_ERROR(
      utils::ToProtoTime(snooze_end_time_, status.mutable_snooze_end_time()));
  notification_thread_->Post(
      [notification, status] { notification->Snoozed(status); });
  return StartSnoozeTimer(new_snooze_duration);
}

absl::Status Reconnector::SetNetwork(std::optional<NetworkInfo> network_info) {
  absl::MutexLock l(&mutex_);
  set_network_called_ = true;

  // Always Store the active network info. This could be used when
  // reconnection timer expires and we might need to restart a session.
  active_network_info_ = network_info;

  // If we are setting a network, reset control plane/datapath failure counters.
  ResetFailureCounters();

  // If the user has snoozed PPN, do nothing and wait until PPN is resumed
  // before trying to SetNetwork().
  if (state_ == kSnoozed) {
    LOG(INFO) << "PPN is snoozed. Will only set active_network_info.";
    return absl::OkStatus();
  }

  // Steps to do when we get Switch Network.
  // a. If going to Airplane mode |NetworkInfo| is nullopt, stop the session and
  //    go to Paused state.
  // b. If we are in Airplane mode and |NetworkInfo| is set,
  //    Start the reconnection.
  // c. If session is active, just pass it to the session.
  if (!network_info) {
    LOG(INFO) << "Entering Airplane mode or no network is available";

    if (session_manager_ != nullptr) {
      TerminateSession(absl::InternalError("No network"),
                       /*forceFailOpen=*/false);
    }
    // Stop any running timers.
    CancelAllTimersIfRunning();
    SetState(kPaused);
    return absl::OkStatus();
  }

  // If we are paused state, resume by trying reconnection.
  if (network_info && state_ == kPaused) {
    LOG(INFO) << "Session is in Paused state, unpausing it";
    StartReconnection();
    return absl::OkStatus();
  }

  // If there is a session, pass on the info.
  if (session_manager_ != nullptr && session_manager_->session()) {
    return session_manager_->session().value()->SetNetwork(
        active_network_info_);
  }

  return absl::OkStatus();
}

DisconnectionStatus Reconnector::GetDisconnectionStatus(
    const absl::Status& reason) {
  DisconnectionStatus status;
  status.set_code(reason.raw_code());
  status.set_message(reason.message());
  status.set_has_available_networks(active_network_info_.has_value());
  status.set_is_blocking_traffic(tunnel_manager_->IsTunnelActive());
  auto details = utils::GetPpnStatusDetails(reason);
  *status.mutable_ppn_status_details() = details;
  return status;
}

void Reconnector::SetSimulatedNetworkFailure(bool simulated_network_failure) {
  LOG(WARNING) << "Setting simulated network failure to "
               << simulated_network_failure;
  if (simulated_network_failure) {
    // Basically, pretend to be snoozed, but without a timer to resume, and not
    // forcing PPN to fail open.
    absl::MutexLock l(&mutex_);
    TerminateSession(absl::InternalError("Simulated network failure"),
                     /*forceFailOpen=*/false);
    CancelAllTimersIfRunning();
    SetState(kSnoozed);
  } else {
    // Resume() will move us out of the snoozed state and start reconnecting.
    PPN_LOG_IF_ERROR(Resume());
  }
}

void Reconnector::GetDebugInfo(ReconnectorDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);

  debug_info->set_state(StateString(state_));
  debug_info->set_session_restart_counter(session_restart_counter_);
  debug_info->set_successive_control_plane_failures(
      std::pow(2, static_cast<double>(successive_control_plane_failures_)));
  debug_info->set_successive_data_plane_failures(
      std::pow(2, static_cast<double>(successive_datapath_failures_)));
}

void Reconnector::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  telemetry->set_control_plane_failures(telemetry_data_.control_plane_failures);
  telemetry->set_data_plane_failures(telemetry_data_.data_plane_failures);
  telemetry->set_session_restarts(telemetry_data_.session_restarts);
  telemetry_data_.Reset();
}

}  // namespace krypton
}  // namespace privacy
