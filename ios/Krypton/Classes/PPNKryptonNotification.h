/*
 * Copyright (C) 2021 Google Inc.
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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNKRYPTONNOTIFICATION_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNKRYPTONNOTIFICATION_H_

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotificationDelegate.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"

namespace privacy {
namespace krypton {

class PPNKryptonNotification : public KryptonNotificationInterface {
 public:
  explicit PPNKryptonNotification(id<PPNKryptonNotificationDelegate> delegate);

  // Krypton lifecycle events.
  void Connected(const ConnectionStatus& status) override;
  void Connecting(const ConnectingStatus& status) override;
  void ControlPlaneConnected() override;
  void StatusUpdated(const ConnectionStatus& status) override;
  void Disconnected(const DisconnectionStatus& status) override;
  void NetworkDisconnected(const NetworkInfo& network_info,
                           const absl::Status& status) override;
  void PermanentFailure(const absl::Status& status) override;
  void Crashed() override;
  void WaitingToReconnect(const ReconnectionStatus& status) override;
  void Snoozed(const SnoozeStatus& status) override;
  void Resumed(const ResumeStatus& status) override;

 private:
  __weak id<PPNKryptonNotificationDelegate> delegate_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNKRYPTONNOTIFICATION_H_
