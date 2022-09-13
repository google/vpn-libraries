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

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNNetworkType.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNUDPSessionManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonService.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotification.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "third_party/absl/status/status.h"

@interface PPNKryptonService (Testing)
- (privacy::krypton::PPNKryptonNotification &)kryptonNotification;
@end

@interface PPNKryptonServiceTest : XCTestCase <PPNKryptonServiceDelegate, PPNUDPSessionManaging>
@end

@implementation PPNKryptonServiceTest {
  PPNKryptonService *_kryptonService;

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

  id OAuthManager = OCMProtocolMock(@protocol(PPNOAuthManaging));
  id virtualNetworkInterfaceManager =
      OCMProtocolMock(@protocol(PPNVirtualNetworkInterfaceManaging));
  _kryptonService = [[PPNKryptonService alloc] initWithOAuthManager:OAuthManager
                                     virtualNetworkInterfaceManager:virtualNetworkInterfaceManager
                                               ppnUDPSessionManager:self
                                                         timerQueue:dispatch_get_main_queue()];
  _kryptonService.delegate = self;
}

- (void)testInitialization {
  XCTAssertNotNil(_kryptonService);
  XCTAssertNotNil(_kryptonService.delegate);
}

- (void)testDelegateConnected {
  XCTAssertFalse(_didConnectedCalled);
  XCTAssertNil(_connectionStatus);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  privacy::krypton::ConnectionStatus status;
  ppnNotification.Connected(status);
  XCTAssertTrue(_didConnectedCalled);
  XCTAssertNotNil(_connectionStatus);
  XCTAssertEqual(_connectionStatus.networkType, PPNNetworkType(status.network_type()));
}

- (void)testDelegateConnecting {
  XCTAssertFalse(_connectingCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  privacy::krypton::ConnectingStatus status;
  ppnNotification.Connecting(status);
  XCTAssertTrue(_connectingCalled);
}

- (void)testDelegateDidConnectControlPlane {
  XCTAssertFalse(_didConnectControlPlaneCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  ppnNotification.ControlPlaneConnected();
  XCTAssertTrue(_didConnectControlPlaneCalled);
}

- (void)testDelegateStatusUpdated {
  XCTAssertFalse(_didUpdateStatusCalled);
  XCTAssertNil(_connectionStatus);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  privacy::krypton::ConnectionStatus status;
  ppnNotification.StatusUpdated(status);
  XCTAssertTrue(_didUpdateStatusCalled);
  XCTAssertNotNil(_connectionStatus);
  XCTAssertEqual(_connectionStatus.networkType, PPNNetworkType(status.network_type()));
}

- (void)testDelegateDisconnect {
  XCTAssertFalse(_didDisconnectCalled);
  XCTAssertNil(_disconnectionStatus);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  privacy::krypton::DisconnectionStatus status;
  status.set_code(static_cast<int>(absl::StatusCode::kUnavailable));
  absl::Status reason(static_cast<absl::StatusCode>(status.code()), status.message());

  ppnNotification.Disconnected(status);
  XCTAssertTrue(_didDisconnectCalled);
  XCTAssertNotNil(_disconnectionStatus);
  NSError *error = privacy::krypton::NSErrorFromPPNStatus(reason);
  XCTAssertEqual(error.code, _disconnectionStatus.disconnectionReason.code);
  XCTAssertEqual(_disconnectionStatus.hasAvailableNetworks, status.has_available_networks());
}

- (void)testDelegateNetworkDisconnected {
  XCTAssertFalse(_didFailWithErrorCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  absl::Status status = absl::Status(absl::StatusCode::kUnavailable, "test network disconnected.");
  ppnNotification.NetworkDisconnected(privacy::krypton::NetworkInfo(), status);
  XCTAssertTrue(_didFailWithErrorCalled);
  XCTAssertNotNil(_error);
  XCTAssertEqualObjects(_error.domain, PPNErrorDomain);
  XCTAssertEqual(_error.code, PPNErrorUnavailable);
  XCTAssertNotNil(_networkInfo);
}

- (void)testDelegatePermanentlyFailWithError {
  XCTAssertFalse(_didPermanentlyFailWithErrorCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  absl::Status status = absl::Status(absl::StatusCode::kUnavailable, "test permanent failure.");
  ppnNotification.PermanentFailure(status);
  XCTAssertTrue(_didPermanentlyFailWithErrorCalled);
  XCTAssertNotNil(_error);
  XCTAssertEqualObjects(_error.domain, PPNErrorDomain);
  XCTAssertEqual(_error.code, PPNErrorUnavailable);
}

- (void)testDelegateCrashed {
  XCTAssertFalse(_didCrashCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  ppnNotification.Crashed();
  XCTAssertTrue(_didCrashCalled);
}

- (void)testDelegateWaitingToReconnect {
  XCTAssertFalse(_waitingToReconnectCalled);
  privacy::krypton::PPNKryptonNotification &ppnNotification = [_kryptonService kryptonNotification];
  privacy::krypton::ReconnectionStatus status;
  ppnNotification.WaitingToReconnect(status);
  XCTAssertTrue(_waitingToReconnectCalled);
  XCTAssertNotNil(_waitingToReconnectStatus);
}

#pragma mark - PPNKryptonServiceDelegate

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
            didConnect:(PPNConnectionStatus *)status {
  _connectionStatus = status;
  _didConnectedCalled = YES;
}

- (void)kryptonServiceConnecting:(PPNKryptonService *)ppnKryptonService {
  _connectingCalled = YES;
}

- (void)kryptonServiceDidConnectControlPlane:(PPNKryptonService *)ppnKryptonService {
  _didConnectControlPlaneCalled = YES;
}

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
       didUpdateStatus:(PPNConnectionStatus *)status {
  _connectionStatus = status;
  _didUpdateStatusCalled = YES;
}

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
         didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus {
  _disconnectionStatus = disconnectionStatus;
  _didDisconnectCalled = YES;
}

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
      didFailWithError:(NSError *)error
           networkInfo:(PPNNetworkInfo *)networkInfo {
  _error = error;
  _networkInfo = networkInfo;
  _didFailWithErrorCalled = YES;
}

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
    didPermanentlyFailWithError:(NSError *)error {
  _error = error;
  _didPermanentlyFailWithErrorCalled = YES;
}

- (void)kryptonServiceDidCrash:(PPNKryptonService *)ppnKryptonService {
  _didCrashCalled = YES;
}

- (void)kryptonService:(PPNKryptonService *)ppnKryptonService
    waitingToReconnect:(PPNReconnectStatus *)status {
  _waitingToReconnectStatus = status;
  _waitingToReconnectCalled = YES;
}

#pragma mark - PPNUDPSessionManaging

- (NWUDPSession *)createUDPSessionToEndpoint:(NWEndpoint *)remoteEndpoint
                                fromEndpoint:(nullable NWHostEndpoint *)localEndpoint {
  // no-op.
  return nil;
}

@end
