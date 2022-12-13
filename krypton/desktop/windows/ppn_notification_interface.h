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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_NOTIFICATION_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_NOTIFICATION_INTERFACE_H_

#include "privacy/net/krypton/proto/connection_status.proto.h"

namespace privacy {
namespace krypton {
namespace windows {

// Listener class for updating the ppn state.
class PpnNotificationInterface {
 public:
  PpnNotificationInterface() = default;
  virtual ~PpnNotificationInterface() = default;

  virtual void PpnStarted() = 0;

  virtual void PpnStopped(const absl::Status& status) = 0;

  virtual void PpnConnected() = 0;

  virtual void PpnConnecting() = 0;

  virtual void PpnDisconnected(
      const privacy::krypton::DisconnectionStatus& status) = 0;

  virtual void PpnWaitingToReconnect() = 0;

  virtual void PpnPermanentFailure(const absl::Status& status) = 0;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_PPN_NOTIFICATION_INTERFACE_H_
