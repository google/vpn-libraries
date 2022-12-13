/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/windows/ppn_telemetry_manager.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/uptime_duration_tracker.h"
#include "privacy/net/krypton/desktop/windows/uptime_tracker.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

PpnTelemetryManager::PpnTelemetryManager(KryptonClock* clock)
    : service_tracker_(clock),
      connection_tracker_(clock),
      network_tracker_(clock),
      disconnection_duration_tracker_(clock) {
  disconnection_count_ = 0;
}

void PpnTelemetryManager::NotifyStarted() {
  running_ = true;
  service_tracker_.Start();
}

void PpnTelemetryManager::NotifyStopped() {
  bool expected = true;
  if (connected_.compare_exchange_strong(expected, false)) {
    LOG(INFO) << "PPN was marked as stopped, even though it's still connected. "
                 "Marking disconnected";
  }
  running_ = false;
  disconnection_duration_tracker_.Stop();
  service_tracker_.Stop();
}

void PpnTelemetryManager::NotifyConnected() {
  if (!running_) {
    LOG(INFO) << "PPN was marked as connected even though the service is not "
                 "running.";
  }
  connected_ = true;
  connection_tracker_.Start();
  disconnection_duration_tracker_.Stop();
  disconnected_ = false;
}

void PpnTelemetryManager::NotifyDisconnected() {
  bool expected = false;
  if (disconnected_.compare_exchange_strong(expected, true)) {
    disconnection_count_++;
  }
  connected_ = false;
  connection_tracker_.Stop();
  disconnection_duration_tracker_.Start();
}

void PpnTelemetryManager::NotifyNetworkAvailable() {
  if (!running_) {
    LOG(INFO)
        << "PPN was marked as network available, but not marked as running.";
  }
  if (disconnected_) {
    disconnection_duration_tracker_.Start();
  }
  network_tracker_.Start();
}

void PpnTelemetryManager::NotifyNetworkUnavailable() {
  if (!running_) {
    LOG(INFO)
        << "PPN was marked as network unavailable, but not marked as running.";
  }
  disconnection_duration_tracker_.Stop();
  network_tracker_.Stop();
}

desktop::PpnTelemetry PpnTelemetryManager::Collect(Krypton* krypton) {
  desktop::PpnTelemetry telemetry;
  KryptonTelemetry krypton_telemetry;
  krypton->CollectTelemetry(&krypton_telemetry);

  // Telemetry from Krypton
  telemetry.set_network_switches(krypton_telemetry.network_switches());
  telemetry.set_successful_rekeys(krypton_telemetry.successful_rekeys());
  telemetry.mutable_auth_latency()->CopyFrom(krypton_telemetry.auth_latency());
  telemetry.mutable_oauth_latency()->CopyFrom(
      krypton_telemetry.oauth_latency());
  telemetry.mutable_egress_latency()->CopyFrom(
      krypton_telemetry.egress_latency());
  telemetry.mutable_zinc_latency()->CopyFrom(krypton_telemetry.zinc_latency());

  PPN_LOG_IF_ERROR(
      utils::ToProtoDuration(connection_tracker_.CollectDuration(),
                             telemetry.mutable_ppn_connection_uptime()));

  PPN_LOG_IF_ERROR(utils::ToProtoDuration(network_tracker_.CollectDuration(),
                                          telemetry.mutable_network_uptime()));

  PPN_LOG_IF_ERROR(
      utils::ToProtoDuration(service_tracker_.CollectDuration(),
                             telemetry.mutable_ppn_service_uptime()));

  for (absl::Duration duration :
       disconnection_duration_tracker_.CollectDurations()) {
    PPN_LOG_IF_ERROR(utils::ToProtoDuration(
        duration, telemetry.add_disconnection_durations()));
  }
  telemetry.set_disconnection_count(disconnection_count_);
  disconnection_count_ = 0;
  return telemetry;
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
