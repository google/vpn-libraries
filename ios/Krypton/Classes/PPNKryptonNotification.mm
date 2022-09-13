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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotification.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNReconnectStatus.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNConnectionStatus+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNDisconnectionStatus+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNNetworkInfo.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNReconnectStatus+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotification.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotificationDelegate.h"

#include "base/logging.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/base/log_severity.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

PPNKryptonNotification::PPNKryptonNotification(id<PPNKryptonNotificationDelegate> delegate)
    : delegate_(delegate) {}

void PPNKryptonNotification::Connected(const ConnectionStatus& status) {
  LOG(INFO) << "Sending Connected notification";
  PPNConnectionStatus* ppnConnectionStatus =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:status];
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:didConnect:)]) {
    [delegate_ kryptonNotification:*this didConnect:ppnConnectionStatus];
  }
};

void PPNKryptonNotification::Connecting(const ConnectingStatus&) {
  LOG(INFO) << "Sending Connecting notification";
  if ([delegate_ respondsToSelector:@selector(kryptonNotificationConnecting:)]) {
    // TODO: Update the delegate with the new metadata.
    [delegate_ kryptonNotificationConnecting:*this];
  }
};

void PPNKryptonNotification::ControlPlaneConnected() {
  LOG(INFO) << "Sending ControlPlaneConnected notification";
  if ([delegate_ respondsToSelector:@selector(kryptonNotificationDidConnectControlPlane:)]) {
    [delegate_ kryptonNotificationDidConnectControlPlane:*this];
  }
};

void PPNKryptonNotification::StatusUpdated(const ConnectionStatus& connectionStatus) {
  LOG(INFO) << "Sending StatusUpdated notification";
  PPNConnectionStatus* ppnConnectionStatus =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:connectionStatus];
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:didUpdateStatus:)]) {
    [delegate_ kryptonNotification:*this didUpdateStatus:ppnConnectionStatus];
  }
};

void PPNKryptonNotification::Disconnected(const DisconnectionStatus& status) {
  LOG(INFO) << "Sending Disconnected notification with code " << status.code() << ": "
            << status.message();
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:didDisconnect:)]) {
    PPNDisconnectionStatus* disconnectionStatus =
        [[PPNDisconnectionStatus alloc] initWithDisconnectionStatus:status];
    [delegate_ kryptonNotification:*this didDisconnect:disconnectionStatus];
  }
};

void PPNKryptonNotification::NetworkDisconnected(const NetworkInfo& network_info,
                                                 const absl::Status& status) {
  LOG(INFO) << "Sending NetworkDisconnected with status " << status;
  NSError* error = privacy::krypton::NSErrorFromPPNStatus(status);
  PPNNetworkInfo* disconnected_network_info =
      [[PPNNetworkInfo alloc] initWithNetworkInfo:network_info];
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:didFailWithError:networkInfo:)]) {
    [delegate_ kryptonNotification:*this
                  didFailWithError:error
                       networkInfo:disconnected_network_info];
  }
};

void PPNKryptonNotification::PermanentFailure(const absl::Status& status) {
  LOG(INFO) << "Sending PermanentFailure notification with code " << status.raw_code() << ": "
            << status;
  NSError* error = privacy::krypton::NSErrorFromPPNStatus(status);
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:didPermanentlyFailWithError:)]) {
    [delegate_ kryptonNotification:*this didPermanentlyFailWithError:error];
  }
};

void PPNKryptonNotification::Crashed() {
  LOG(INFO) << "Sending Crashed notification";
  if ([delegate_ respondsToSelector:@selector(kryptonNotificationDidCrash:)]) {
    [delegate_ kryptonNotificationDidCrash:*this];
  }
};

void PPNKryptonNotification::WaitingToReconnect(const ReconnectionStatus& status) {
  auto status_or_time_to_reconnect = utils::DurationFromProto(status.time_to_reconnect());
  if (!status_or_time_to_reconnect.ok()) {
    LOG(ERROR) << "Invalid time to reconnect.";
    return;
  }

  NSTimeInterval reconnectInterval = absl::ToDoubleSeconds(*status_or_time_to_reconnect);
  LOG(INFO) << "Sending WaitingToReconnect notification: " << reconnectInterval;
  // TODO: Update the delegate with the new metadata.
  PPNReconnectStatus* ppnReconnectStatus =
      [[PPNReconnectStatus alloc] initWithRetryInterval:reconnectInterval];
  if ([delegate_ respondsToSelector:@selector(kryptonNotification:waitingToReconnect:)]) {
    [delegate_ kryptonNotification:*this waitingToReconnect:ppnReconnectStatus];
  }
};

// Empty method here as Snooze feature is not supported in iOS.
void PPNKryptonNotification::Snoozed(const SnoozeStatus&) {}

// Empty method here as Snooze feature is not supported in iOS.
void PPNKryptonNotification::Resumed(const ResumeStatus&) {}

}  // namespace krypton
}  // namespace privacy
