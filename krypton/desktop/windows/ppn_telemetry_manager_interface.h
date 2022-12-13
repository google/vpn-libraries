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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_INTERFACE_H_

#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"

namespace privacy {
namespace krypton {
namespace windows {

// Tracking uptime and disconnections.
class PpnTelemetryManagerInterface {
 public:
  PpnTelemetryManagerInterface() = default;
  virtual ~PpnTelemetryManagerInterface() = default;

  // Should be called when the PPN service is started.
  virtual void NotifyStarted() = 0;

  // Should be called when the PPN service stops.
  virtual void NotifyStopped() = 0;

  // Should be called when PPN connects.
  virtual void NotifyConnected() = 0;

  // Should be called when PPN disconnects.
  virtual void NotifyDisconnected() = 0;

  // Should be called when any network is available.
  virtual void NotifyNetworkAvailable() = 0;

  // Should be called when no network is available.
  virtual void NotifyNetworkUnavailable() = 0;

  // Returns a collection of the metrics since the last time collect was called,
  // and resets them.
  virtual desktop::PpnTelemetry Collect(Krypton* krypton) = 0;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_TELEMETRY_MANAGER_INTERFACE_H_
