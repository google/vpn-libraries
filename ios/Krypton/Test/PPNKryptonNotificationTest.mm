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

#import <XCTest/XCTest.h>
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotification.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotificationDelegate.h"

#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "third_party/absl/status/status.h"

@interface PPNKryptonNotificationTest : XCTestCase <PPNKryptonNotificationDelegate>
@end

@implementation PPNKryptonNotificationTest {
  std::unique_ptr<privacy::krypton::PPNKryptonNotification> _ppn_krypton_notification;

  bool _didConnectedCalled;
  bool _connectingCalled;
  bool _didConnectControlPlaneCalled;
  bool _didUpdateStatusCalled;
  bool _didDisconnectCalled;
  bool _didFailWithErrorCalled;
  bool _didPermanentlyFailWithErrorCalled;
  bool _didCrashCalled;
  bool _waitingToReconnectCalled;

  PPNConnectionStatus *_connectionStatus;
  PPNDisconnectionStatus *_disconnectionStatus;
  NSError *_error;
  PPNNetworkInfo *_networkInfo;
  PPNReconnectStatus *_waitingToReconnectStatus;
}

- (void)setUp {
  [super setUp];
  _ppn_krypton_notification = std::make_unique<privacy::krypton::PPNKryptonNotification>(self);
}

- (void)testConnected {
  XCTAssertFalse(_didConnectedCalled);
  XCTAssertNil(_connectionStatus);
  privacy::krypton::ConnectionStatus status;
  _ppn_krypton_notification->Connected(status);
  XCTAssertTrue(_didConnectedCalled);
  XCTAssertNotNil(_connectionStatus);
}

- (void)testConnecting {
  XCTAssertFalse(_connectingCalled);
  privacy::krypton::ConnectingStatus status;
  _ppn_krypton_notification->Connecting(status);
  XCTAssertTrue(_connectingCalled);
}

- (void)testControlPlaneConnected {
  XCTAssertFalse(_didConnectControlPlaneCalled);
  _ppn_krypton_notification->ControlPlaneConnected();
  XCTAssertTrue(_didConnectControlPlaneCalled);
}

- (void)testStatusUpdated {
  XCTAssertFalse(_didUpdateStatusCalled);
  XCTAssertNil(_connectionStatus);
  privacy::krypton::ConnectionStatus status;
  _ppn_krypton_notification->StatusUpdated(status);
  XCTAssertTrue(_didUpdateStatusCalled);
  XCTAssertNotNil(_connectionStatus);
}

- (void)testDisconnected {
  XCTAssertFalse(_didDisconnectCalled);
  XCTAssertNil(_disconnectionStatus);
  privacy::krypton::DisconnectionStatus status;
  status.set_code(static_cast<int>(absl::StatusCode::kUnavailable));
  _ppn_krypton_notification->Disconnected(status);
  XCTAssertTrue(_didDisconnectCalled);
  XCTAssertNotNil(_disconnectionStatus);
}

- (void)testNetworkDisconnected {
  XCTAssertFalse(_didFailWithErrorCalled);
  absl::Status status = absl::Status(absl::StatusCode::kUnavailable, "test network disconnected.");
  _ppn_krypton_notification->NetworkDisconnected(privacy::krypton::NetworkInfo(), status);
  XCTAssertTrue(_didFailWithErrorCalled);
  XCTAssertNotNil(_error);
  XCTAssertEqualObjects(_error.domain, PPNErrorDomain);
  XCTAssertEqual(_error.code, PPNErrorUnavailable);
  XCTAssertNotNil(_networkInfo);
}

- (void)testPermanentFailure {
  XCTAssertFalse(_didPermanentlyFailWithErrorCalled);
  absl::Status status = absl::Status(absl::StatusCode::kUnavailable, "test permanent failure.");
  _ppn_krypton_notification->PermanentFailure(status);
  XCTAssertTrue(_didPermanentlyFailWithErrorCalled);
  XCTAssertNotNil(_error);
  XCTAssertEqualObjects(_error.domain, PPNErrorDomain);
  XCTAssertEqual(_error.code, PPNErrorUnavailable);
}

- (void)testCrashed {
  XCTAssertFalse(_didCrashCalled);
  _ppn_krypton_notification->Crashed();
  XCTAssertTrue(_didCrashCalled);
}

- (void)testWaitingToReconnect {
  XCTAssertFalse(_waitingToReconnectCalled);
  privacy::krypton::ReconnectionStatus status;
  _ppn_krypton_notification->WaitingToReconnect(status);
  XCTAssertTrue(_waitingToReconnectCalled);
  XCTAssertNotNil(_waitingToReconnectStatus);
}

#pragma mark - PPNKryptonNotificationDelegate

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
                 didConnect:(PPNConnectionStatus *)status {
  _connectionStatus = status;
  _didConnectedCalled = YES;
}

- (void)kryptonNotificationConnecting:
    (privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification {
  _connectingCalled = YES;
}

- (void)kryptonNotificationDidConnectControlPlane:
    (privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification {
  _didConnectControlPlaneCalled = YES;
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
            didUpdateStatus:(PPNConnectionStatus *)status {
  _connectionStatus = status;
  _didUpdateStatusCalled = YES;
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
              didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus {
  _disconnectionStatus = disconnectionStatus;
  _didDisconnectCalled = YES;
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
           didFailWithError:(NSError *)error
                networkInfo:(PPNNetworkInfo *)networkInfo {
  _error = error;
  _networkInfo = networkInfo;
  _didFailWithErrorCalled = YES;
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
    didPermanentlyFailWithError:(NSError *)error {
  _error = error;
  _didPermanentlyFailWithErrorCalled = YES;
}

- (void)kryptonNotificationDidCrash:
    (privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification {
  _didCrashCalled = YES;
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)ppnKryptonNotification
         waitingToReconnect:(PPNReconnectStatus *)status {
  _waitingToReconnectStatus = status;
  _waitingToReconnectCalled = YES;
}

@end
