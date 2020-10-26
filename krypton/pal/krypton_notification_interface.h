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

#ifndef PRIVACY_NET_KRYPTON_PAL_KRYPTON_NOTIFICATION_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_KRYPTON_NOTIFICATION_INTERFACE_H_

#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"

// Interface for notifying PPN library about events happening in Krypton.
namespace privacy {
namespace krypton {

class KryptonNotificationInterface {
 public:
  KryptonNotificationInterface() = default;
  virtual ~KryptonNotificationInterface() = default;

  // Lifecycle events.
  virtual void Connected() = 0;
  virtual void Connecting() = 0;
  virtual void ControlPlaneConnected() = 0;
  virtual void StatusUpdated() = 0;
  virtual void Disconnected(const absl::Status& status) = 0;
  virtual void NetworkDisconnected(const NetworkInfo& network_info,
                                   const absl::Status& status) = 0;
  virtual void PermanentFailure(const absl::Status& status) = 0;
  virtual void Crashed() = 0;
  virtual void WaitingToReconnect(const int64 retry_millis) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_KRYPTON_NOTIFICATION_INTERFACE_H_
