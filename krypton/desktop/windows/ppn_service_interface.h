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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_INTERFACE_H_

#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/desktop/proto/ppn_telemetry.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"

namespace privacy {
namespace krypton {
namespace windows {

// The PPN service that controls the VPN.
class PpnServiceInterface {
 public:
  PpnServiceInterface() = default;
  virtual ~PpnServiceInterface() = default;

  // Starts PPN
  virtual void Start(const KryptonConfig& config) = 0;

  // Stops PPN
  virtual void Stop(const absl::Status& status) = 0;

  // Returns a PpnTelemetry object with data about how PPN is currently
  // running.
  virtual absl::StatusOr<desktop::PpnTelemetry> CollectTelemetry() = 0;

  // Sets the geographical granularity of IP allocation.
  virtual absl::Status SetIpGeoLevel(ppn::IpGeoLevel level) = 0;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_SERVICE_INTERFACE_H_
