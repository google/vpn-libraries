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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_H_

#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/desktop/windows/ppn_telemetry_manager_interface.h"
#include "privacy/net/krypton/desktop/windows/uptime_duration_tracker.h"
#include "privacy/net/krypton/desktop/windows/uptime_tracker.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/krypton_clock.h"

namespace privacy {
namespace krypton {
namespace windows {

// Tracking uptime and disconnections.
class PpnTelemetryManager : public PpnTelemetryManagerInterface {
 public:
  explicit PpnTelemetryManager(KryptonClock* clock);
  ~PpnTelemetryManager() override = default;

  // Should be called when the PPN service is started.
  void NotifyStarted() override;

  // Should be called when the PPN service stops.
  void NotifyStopped() override;

  // Should be called when PPN connects.
  void NotifyConnected() override;

  // Should be called when PPN disconnects.
  void NotifyDisconnected() override;

  // Should be called when any network is available.
  void NotifyNetworkAvailable() override;

  // Should be called when no network is available.
  void NotifyNetworkUnavailable() override;

  // Returns a collection of the metrics since the last time collect was called,
  // and resets them.
  desktop::PpnTelemetry Collect(Krypton* krypton) override;

 private:
  UptimeTracker service_tracker_;
  UptimeTracker connection_tracker_;
  UptimeTracker network_tracker_;
  UptimeDurationTracker disconnection_duration_tracker_;
  std::atomic_int disconnection_count_;

  // Track the state to double-check events are consistent.
  std::atomic_bool running_ = false;
  std::atomic_bool connected_ = false;
  // !Connected can't be used as disconnected as Connected and Disconnected both
  // will be false before the first time PPN has connected.
  std::atomic_bool disconnected_ = false;
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_H_
