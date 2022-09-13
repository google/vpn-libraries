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

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNService.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNUDPSessionManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNConnectionStatus+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNDisconnectionStatus+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonService.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitor.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

#include "privacy/net/krypton/proto/krypton_config.proto.h"

#import <XCTest/XCTest.h>

static NSTimeInterval const PPNTimeoutInterval = 1.0;

// Fakes the PPNKryptonService for testing.
@interface FakePPNKryptonService : PPNKryptonService
@property(nonatomic, readonly) BOOL kryptonStartCalled;
@property(nonatomic, readonly) BOOL kryptonStopCalled;
@property(nonatomic, readonly) BOOL kryptonCollectTelemetryCalled;
@end

@implementation FakePPNKryptonService

- (void)startWithConfiguration:(const privacy::krypton::KryptonConfig &)configuration {
  _kryptonStartCalled = YES;
  return;
}

- (void)stop {
  _kryptonStopCalled = YES;
  return;
}

- (privacy::krypton::KryptonTelemetry)collectTelemetry {
  privacy::krypton::KryptonTelemetry fakeKryptonTelemetry;
  _kryptonCollectTelemetryCalled = YES;
  return fakeKryptonTelemetry;
}

- (privacy::krypton::KryptonDebugInfo)debugInfo {
  privacy::krypton::KryptonDebugInfo debugInfo;
  return debugInfo;
}

@end

// Fakes the PPNNWPathMonitor for testing.
@interface FakePPNNWPathMonitor : PPNNWPathMonitor
@property(nonatomic, readonly) BOOL startMonitorCalled;
@property(nonatomic, readonly) BOOL stopMonitorCalled;
@end

@implementation FakePPNNWPathMonitor

- (void)startMonitor {
  _startMonitorCalled = YES;
  return;
}

- (void)stopMonitor {
  _stopMonitorCalled = YES;
  return;
}

@end

@interface PPNServiceTest : XCTestCase <PPNServiceDelegate>
@end

@implementation PPNServiceTest {
  PPNService *_PPNService;
  XCTestExpectation *_didStartExpectation;
  XCTestExpectation *_connectingExpectation;
  XCTestExpectation *_didStopExpectation;
  XCTestExpectation *_didConnectExpectation;
  XCTestExpectation *_didUpdateStatusExpectation;
  XCTestExpectation *_didDisconnectExpectation;
  XCTestExpectation *_waitingToReconnectExpectation;

  NSError *_error;
  PPNConnectionStatus *_connectionStatus;
  PPNDisconnectionStatus *_disconnectionStatus;
  PPNKryptonService *_kryptonService;
  PPNNWPathMonitor *_nwPathMonitor;
}

- (void)setUp {
  [super setUp];
  id OAuthManager = OCMProtocolMock(@protocol(PPNOAuthManaging));
  id virtualNetworkInterfaceManager =
      OCMProtocolMock(@protocol(PPNVirtualNetworkInterfaceManaging));
  id UDPSessionManager = OCMProtocolMock(@protocol(PPNUDPSessionManaging));
  NSDictionary<PPNOptionKey, id> *options = @{
    PPNOptionZincURLString : @"https://staging.zinc.cloud.cupronickel.goog/auth",
  };
  _PPNService = [[PPNService alloc] initWithOptions:options
                                       OAuthManager:OAuthManager
                     virtualNetworkInterfaceManager:virtualNetworkInterfaceManager
                                  UDPSessionManager:UDPSessionManager];
  _PPNService.delegate = self;

  _kryptonService = [_PPNService valueForKey:@"_kryptonService"];
  XCTAssertNotNil(_kryptonService);

  _nwPathMonitor = [_PPNService valueForKey:@"_nwPathMonitor"];
  XCTAssertNotNil(_nwPathMonitor);

  _didStartExpectation =
      [[XCTestExpectation alloc] initWithDescription:@"should call -PPNServiceDidStart:"];
  _connectingExpectation =
      [[XCTestExpectation alloc] initWithDescription:@"should call -PPNServiceConnecting:"];
  _didStopExpectation =
      [[XCTestExpectation alloc] initWithDescription:@"should call -PPNService:didStopWithError:"];
  _didConnectExpectation = [[XCTestExpectation alloc]
      initWithDescription:@"should call -PPNService:didConnectWithStatus:"];
  _didUpdateStatusExpectation =
      [[XCTestExpectation alloc] initWithDescription:@"should call -PPNService:didUpdateStatus:"];
  _didDisconnectExpectation = [[XCTestExpectation alloc]
      initWithDescription:@"should call -PPNService:didDisconnectWithError:"];
  _waitingToReconnectExpectation = [[XCTestExpectation alloc]
      initWithDescription:@"should call -PPNService:waitingToReconnect:"];

  _error = nil;
}

- (void)testInitialization {
  XCTAssertNotNil(_PPNService);
  XCTAssertNotNil(_PPNService.delegate);
  XCTAssertTrue([_kryptonService isKindOfClass:[PPNKryptonService class]]);
}

- (void)testRunning {
  FakePPNKryptonService *fakeKryptonService = [[FakePPNKryptonService alloc] init];
  [_PPNService setValue:fakeKryptonService forKey:@"kryptonService"];

  FakePPNNWPathMonitor *fakePPNNWPathMonitor = [[FakePPNNWPathMonitor alloc] init];
  [_PPNService setValue:fakePPNNWPathMonitor forKey:@"nwPathMonitor"];

  XCTAssertFalse(_PPNService.isRunning);

  [_PPNService start];
  [self waitForExpectations:@[ _didStartExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertTrue(_PPNService.isRunning);
  XCTAssertTrue(fakeKryptonService.kryptonStartCalled);
  XCTAssertTrue(fakePPNNWPathMonitor.startMonitorCalled);

  [_PPNService stop];
  [self waitForExpectations:@[ _didStopExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertFalse(_PPNService.isRunning);
  XCTAssertTrue(fakeKryptonService.kryptonStopCalled);
  XCTAssertTrue(fakePPNNWPathMonitor.stopMonitorCalled);
}

- (void)testCollectTelemetry {
  FakePPNKryptonService *fakeKryptonService = [[FakePPNKryptonService alloc] init];
  [_PPNService setValue:fakeKryptonService forKey:@"kryptonService"];

  [_PPNService collectTelemetry];
  XCTAssertTrue(fakeKryptonService.kryptonCollectTelemetryCalled);
}

- (void)testKryptonStop {
  FakePPNKryptonService *fakeKryptonService = [[FakePPNKryptonService alloc] init];
  [_PPNService setValue:fakeKryptonService forKey:@"kryptonService"];

  [_PPNService stop];

  [self waitForExpectations:@[ _didStopExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertNil(_error);
  XCTAssertTrue(fakeKryptonService.kryptonStopCalled);
}

- (void)testKryptonDidConnect {
  privacy::krypton::ConnectionStatus connectionStatus;
  PPNConnectionStatus *status =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:connectionStatus];
  [_kryptonService.delegate kryptonService:_kryptonService didConnect:status];

  [self waitForExpectations:@[ _didConnectExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertEqualObjects(_connectionStatus, status);
}

- (void)testKryptonDidDisconnect {
  privacy::krypton::DisconnectionStatus disconnectionStatus;
  PPNDisconnectionStatus *status =
      [[PPNDisconnectionStatus alloc] initWithDisconnectionStatus:disconnectionStatus];
  [_kryptonService.delegate kryptonService:_kryptonService didDisconnect:status];

  [self waitForExpectations:@[ _didDisconnectExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertEqualObjects(_disconnectionStatus, status);
}

- (void)testKryptonDidUpdateStatus {
  privacy::krypton::ConnectionStatus connectionStatus;
  PPNConnectionStatus *status =
      [[PPNConnectionStatus alloc] initWithConnectionStatus:connectionStatus];
  [_kryptonService.delegate kryptonService:_kryptonService didUpdateStatus:status];

  [self waitForExpectations:@[ _didUpdateStatusExpectation ] timeout:PPNTimeoutInterval];
  XCTAssertEqualObjects(_connectionStatus, status);
}

- (void)testKryptonDidPermanentlyFail {
  FakePPNKryptonService *fakeKryptonService = [[FakePPNKryptonService alloc] init];
  [_PPNService setValue:fakeKryptonService forKey:@"kryptonService"];

  FakePPNNWPathMonitor *fakePPNNWPathMonitor = [[FakePPNNWPathMonitor alloc] init];
  [_PPNService setValue:fakePPNNWPathMonitor forKey:@"nwPathMonitor"];

  [_PPNService start];
  NSError *error = [[NSError alloc] initWithDomain:PPNErrorDomain
                                              code:PPNErrorInternal
                                          userInfo:@{NSLocalizedDescriptionKey : @"test"}];

  [self waitForExpectations:@[ _didStartExpectation ] timeout:PPNTimeoutInterval];

  [_kryptonService.delegate kryptonService:_kryptonService didPermanentlyFailWithError:error];

  [self waitForExpectations:@[ _didStopExpectation ] timeout:PPNTimeoutInterval];

  XCTAssertEqualObjects(_error, error);
}

#pragma mark - PPNServiceDelegate

- (void)PPNServiceDidStart:(PPNService *)PPNService {
  [_didStartExpectation fulfill];
}

- (void)PPNServiceConnecting:(PPNService *)PPNService {
  [_connectingExpectation fulfill];
}

- (void)PPNService:(PPNService *)PPNService didStopWithError:(nullable NSError *)error {
  _error = error;
  [_didStopExpectation fulfill];
}

- (void)PPNService:(PPNService *)PPNService
    didConnectWithStatus:(PPNConnectionStatus *)connectionStatus {
  _connectionStatus = connectionStatus;
  [_didConnectExpectation fulfill];
}

- (void)PPNService:(PPNService *)PPNService
    didUpdateStatus:(PPNConnectionStatus *)connectionStatus {
  _connectionStatus = connectionStatus;
  [_didUpdateStatusExpectation fulfill];
}

- (void)PPNService:(PPNService *)PPNService
     didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus {
  _disconnectionStatus = disconnectionStatus;
  [_didDisconnectExpectation fulfill];
}

- (void)PPNService:(PPNService *)PPNService waitingToReconnect:(PPNReconnectStatus *)status {
  [_waitingToReconnectExpectation fulfill];
}

@end
