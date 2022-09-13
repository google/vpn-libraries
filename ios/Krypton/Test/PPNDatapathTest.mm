// Copyright 2021 Google LLC
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

#import <XCTest/XCTest.h>

#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

#include <memory>
#include <utility>

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNDatapath.h"

#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/test_packet_pipe.h"
#include "privacy/net/krypton/timer_manager.h"
#include "third_party/absl/time/time.h"

constexpr NSTimeInterval kTimeout = 30.0;

namespace privacy {
namespace krypton {

// OCMock doesn't work for C++ classes, and GMock doesn't play nice with Objective-C tests.
// Therefore, these tests use custom fakes wherever possible instead.

// A helper for testing notifications send from the datapath.
class TestNotification : public DatapathInterface::NotificationInterface {
 public:
  TestNotification() {}
  ~TestNotification() override {}

  XCTestExpectation *ExpectDatapathEstablished() {
    return AddExpectation(@"DatapathEstablished", _establishedExpectations);
  }

  XCTestExpectation *ExpectDatapathFailed() {
    return AddExpectation(@"DatapathFailed", _failedExpectations);
  }

  XCTestExpectation *ExpectDatapathPermanentFailure() {
    return AddExpectation(@"DatapathPermanentFailure", _permanentFailureExpectations);
  }

  void DatapathEstablished() override {
    FulfillExpectation(@"DatapathEstablished", _establishedExpectations);
  }

  void DatapathFailed(const absl::Status &) override {
    FulfillExpectation(@"DatapathFailed", _failedExpectations);
  }

  void DatapathPermanentFailure(const absl::Status &) override {
    FulfillExpectation(@"DatapathPermanentFailure", _permanentFailureExpectations);
  }

  void DoRekey() override {}

  void VerifyNoMoreNotifications() {
    if (_unexpectedNotifications.count > 0) {
      XCTFail(@"Unexpected notifications: %@",
              [_unexpectedNotifications componentsJoinedByString:@", "]);
    }
  }

 private:
  XCTestExpectation *AddExpectation(NSString *name, NSMutableArray<XCTestExpectation *> *array) {
    LOG(INFO) << "Adding expectation " << name.UTF8String;
    XCTestExpectation *expectation = [[XCTestExpectation alloc] initWithDescription:name];
    [array addObject:expectation];
    return expectation;
  }

  void FulfillExpectation(NSString *name, NSMutableArray<XCTestExpectation *> *array) {
    LOG(INFO) << "Fulfilling expectation " << name.UTF8String;
    if (array.count < 1) {
      [_unexpectedNotifications addObject:name];
      return;
    }
    XCTestExpectation *expectation = array.firstObject;
    [array removeObjectAtIndex:0];
    [expectation fulfill];
  }

  NSMutableArray<XCTestExpectation *> *_establishedExpectations = [NSMutableArray array];
  NSMutableArray<XCTestExpectation *> *_failedExpectations = [NSMutableArray array];
  NSMutableArray<XCTestExpectation *> *_permanentFailureExpectations = [NSMutableArray array];
  NSMutableArray<NSString *> *_unexpectedNotifications = [NSMutableArray array];
};

class FakePPNDatapathVpnService : public PPNDatapath::PPNDatapathVpnServiceInterface {
 public:
  FakePPNDatapathVpnService(id mockUDPSession, id mockPacketTunnelFlow)
      : mock_udp_session_(mockUDPSession),
        mock_packet_tunnel_flow_(mockPacketTunnelFlow),
        connection_status_ready_(false) {}

  ~FakePPNDatapathVpnService() override {
    // Make sure any outstanding healthchecks finish.
    FulfillHealthCheck(absl::OkStatus());
  }

  DatapathInterface *BuildDatapath(const KryptonConfig &, utils::LooperThread *,
                                   TimerManager *) override {
    // We're testing the datapath, so the method to create a datapath shouldn't be called.
    LOG(FATAL) << "Tried to BuildDatapath in datapath test.";
    return nullptr;
  }

  absl::Status CreateTunnel(const TunFdData &) override { return absl::OkStatus(); }

  void CloseTunnel() override {}

  absl::Status CheckConnection() override {
    absl::MutexLock l(&mutex_);
    LOG(INFO) << "Connection check started.";
    while (!connection_status_ready_) {
      connection_condition_.Wait(&mutex_);
    }
    LOG(INFO) << "Returning connection status: " << connection_status_;
    return connection_status_;
  }

  void FulfillHealthCheck(absl::Status status) {
    absl::MutexLock l(&mutex_);
    connection_status_ = status;
    connection_status_ready_ = true;
    LOG(INFO) << "Setting connection status: " << connection_status_;
    connection_condition_.SignalAll();
  }

  absl::StatusOr<NWUDPSession *> CreateUDPSession(const NetworkInfo &, const Endpoint &) override {
    return mock_udp_session_;
  }

  NEPacketTunnelFlow *GetPacketTunnelFlow() override { return mock_packet_tunnel_flow_; }

 private:
  id mock_udp_session_;
  id mock_packet_tunnel_flow_;

  absl::Mutex mutex_;
  absl::CondVar connection_condition_ ABSL_GUARDED_BY(mutex_);
  absl::Status connection_status_ ABSL_GUARDED_BY(mutex_);
  bool connection_status_ready_ ABSL_GUARDED_BY(mutex_);
};

class FakeTimerInterface : public TimerInterface {
  absl::Status StartTimer(int, absl::Duration) override { return absl::OkStatus(); }
  void CancelTimer(int) override {}
};

KryptonConfig CreateTestConfig() {
  KryptonConfig config;
  config.set_periodic_health_check_enabled(true);
  config.mutable_periodic_health_check_duration()->set_seconds(300);
  return config;
}

}  // namespace krypton
}  // namespace privacy

@interface PPNDatapathTest : XCTestCase
@end

@implementation PPNDatapathTest {
  privacy::krypton::AddEgressResponse _fakeAddEgressResponse;

  id _mockUDPSession;
  id _mockPacketTunnelFlow;

  std::unique_ptr<privacy::krypton::utils::LooperThread> _looper;
  std::unique_ptr<privacy::krypton::FakeTimerInterface> _timerInterface;
  std::unique_ptr<privacy::krypton::TimerManager> _timerManager;
  std::unique_ptr<privacy::krypton::PPNDatapath> _datapath;
  std::unique_ptr<privacy::krypton::FakePPNDatapathVpnService> _VPNService;

  std::unique_ptr<privacy::krypton::TestNotification> _notification;
}

- (void)setUp {
  [super setUp];

  _mockUDPSession = OCMClassMock([NWUDPSession class]);
  _mockPacketTunnelFlow = OCMClassMock([NEPacketTunnelFlow class]);

  ::privacy::krypton::KryptonConfig config = ::privacy::krypton::CreateTestConfig();
  _looper = std::make_unique<privacy::krypton::utils::LooperThread>("Krypton Looper");
  _timerInterface = std::make_unique<privacy::krypton::FakeTimerInterface>();
  _timerManager = std::make_unique<privacy::krypton::TimerManager>(_timerInterface.get());
  _VPNService = std::make_unique<privacy::krypton::FakePPNDatapathVpnService>(
      _mockUDPSession, _mockPacketTunnelFlow);
  _datapath = std::make_unique<privacy::krypton::PPNDatapath>(
      config, _looper.get(), _VPNService.get(), _timerManager.get());

  _notification = std::make_unique<privacy::krypton::TestNotification>();
  _datapath->RegisterNotificationHandler(_notification.get());
}

- (void)tearDown {
  // It is necessary to explicitly stop the thread and join it before we destroy the other class
  // members, or else queued up runnables may reference members after they are destroyed. But we
  // don't want to destroy the thread yet, because other members may still try to put stuff on it.
  _looper->Stop();
  _looper->Join();

  // Once the looper is joined, there should be no more notifications that weren't expected.
  _notification->VerifyNoMoreNotifications();

  _datapath = nullptr;
  _VPNService = nullptr;
  _timerManager = nullptr;
  _timerInterface = nullptr;
  _looper = nullptr;

  _notification = nullptr;

  _mockPacketTunnelFlow = nil;
  _mockUDPSession = nil;

  [super tearDown];
}

- (void)testSwitchNetworkFailureNoTunnelSocket {
  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kFailedPrecondition, status.code());
}

- (void)testSwitchNetworkFailureNoIpSecParams {
  ::privacy::krypton::TransformParams params;
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kInvalidArgument, status.code());
}

- (void)testSwitchNetworkFailureNoUplinkKey {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kInvalidArgument, status.code());
}

- (void)testSwitchNetworkFailureNoDownlinkKey {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kInvalidArgument, status.code());
}

- (void)testSwitchNetworkFailureNoUplinkSalt {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kInvalidArgument, status.code());
}

- (void)testSwitchNetworkFailureNoDownlinkSalt {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  auto status = _datapath->SwitchNetwork(1, endpoint, network_info, 1);
  XCTAssertEqual(absl::StatusCode::kInvalidArgument, status.code());
}

- (void)testSwitchNetworkHappyPath {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  params.mutable_ipsec()->set_downlink_salt(std::string(4, 'a'));

  LOG(INFO) << "Starting datapath...";
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  // Simulate some network traffic, so that we know everything is running.
  XCTestExpectation *established = _notification->ExpectDatapathEstablished();

  // Make a fake packet to send back to the datapath from the backend.
  ASSERT_OK_AND_ASSIGN(auto encryptor,
                       privacy::krypton::datapath::ipsec::Encryptor::Create(2, params));
  privacy::krypton::Packet unencrypted("foo", 3, privacy::krypton::IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor->Process(unencrypted));
  NSArray<NSData *> *datagrams = @[ [NSData dataWithBytes:encrypted.data().data()
                                                   length:encrypted.data().size()] ];

  // Set up the mock pipe to receive the packet
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  LOG(INFO) << "Switching network...";
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  // Wait for the datapath to be connected.
  [self waitForExpectations:@[ established ] timeout:kTimeout];

  LOG(INFO) << "Stopping datapath...";
  _datapath->Stop();
}

- (void)testHealthCheckFailed {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  params.mutable_ipsec()->set_downlink_salt(std::string(4, 'a'));

  LOG(INFO) << "Starting datapath...";
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  // Simulate some network traffic, so that we know everything is running.
  XCTestExpectation *established = _notification->ExpectDatapathEstablished();

  // Make a fake packet to send back to the datapath from the backend.
  ASSERT_OK_AND_ASSIGN(auto encryptor,
                       privacy::krypton::datapath::ipsec::Encryptor::Create(2, params));
  privacy::krypton::Packet unencrypted("foo", 3, privacy::krypton::IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor->Process(unencrypted));
  NSArray<NSData *> *datagrams = @[ [NSData dataWithBytes:encrypted.data().data()
                                                   length:encrypted.data().size()] ];

  // Set up the mock pipe to receive the packet
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  LOG(INFO) << "Switching network...";
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  // Wait for the datapath to be connected.
  LOG(INFO) << "Waiting for establishment...";
  [self waitForExpectations:@[ established ] timeout:kTimeout];

  // Verify that the health check failing fails the datapath.
  LOG(INFO) << "Failing health check...";
  XCTestExpectation *failed = _notification->ExpectDatapathFailed();
  _timerInterface->TimerExpiry(1);
  _VPNService->FulfillHealthCheck(absl::UnknownError("test error"));
  [self waitForExpectations:@[ failed ] timeout:kTimeout];

  LOG(INFO) << "Stopping datapath...";
  _datapath->Stop();
}

- (void)testSwitchNetworkWhenHealthCheckIsInProgress {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  params.mutable_ipsec()->set_downlink_salt(std::string(4, 'a'));

  LOG(INFO) << "Starting datapath...";
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  // Simulate some network traffic, so that we know everything is running.
  XCTestExpectation *established = _notification->ExpectDatapathEstablished();

  // Make a fake packet to send back to the datapath from the backend.
  ASSERT_OK_AND_ASSIGN(auto encryptor,
                       privacy::krypton::datapath::ipsec::Encryptor::Create(2, params));
  privacy::krypton::Packet unencrypted("foo", 3, privacy::krypton::IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor->Process(unencrypted));
  NSArray<NSData *> *datagrams = @[ [NSData dataWithBytes:encrypted.data().data()
                                                   length:encrypted.data().size()] ];

  // Set up the mock pipe to receive the packet
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  LOG(INFO) << "Switching network...";
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  // Wait for the datapath to be connected.
  [self waitForExpectations:@[ established ] timeout:kTimeout];

  LOG(INFO) << "Switching network again...";
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  // Verify that the *first* health check failing doesn't do anything.
  LOG(INFO) << "Failing health check...";
  _timerInterface->TimerExpiry(1);
  _VPNService->FulfillHealthCheck(absl::UnknownError("test error"));

  LOG(INFO) << "Stopping datapath...";
  _datapath->Stop();
}

- (void)testSwitchingNetworksDoesntSendDuplicateConnectedNotifications {
  ::privacy::krypton::TransformParams params;
  params.mutable_ipsec()->set_uplink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_downlink_key(std::string(32, 'z'));
  params.mutable_ipsec()->set_uplink_salt(std::string(4, 'a'));
  params.mutable_ipsec()->set_downlink_salt(std::string(4, 'a'));

  LOG(INFO) << "Starting datapath...";
  XCTAssertTrue(_datapath->Start(_fakeAddEgressResponse, params).ok());

  // Simulate some network traffic, so that we know everything is running.
  XCTestExpectation *established = _notification->ExpectDatapathEstablished();

  // Make a fake packet to send back to the datapath from the backend.
  ASSERT_OK_AND_ASSIGN(auto encryptor,
                       privacy::krypton::datapath::ipsec::Encryptor::Create(2, params));
  privacy::krypton::Packet unencrypted("foo", 3, privacy::krypton::IPProtocol::kIPv4, [] {});
  ASSERT_OK_AND_ASSIGN(auto encrypted, encryptor->Process(unencrypted));
  NSArray<NSData *> *datagrams = @[ [NSData dataWithBytes:encrypted.data().data()
                                                   length:encrypted.data().size()] ];

  // Set up the mock pipe to receive the packet
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  privacy::krypton::Endpoint endpoint{"192.0.2.0:8080", "192.0.2.0", 8080,
                                      privacy::krypton::IPProtocol::kIPv4};
  privacy::krypton::NetworkInfo network_info;
  LOG(INFO) << "Switching network...";
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  // Wait for the datapath to be connected.
  [self waitForExpectations:@[ established ] timeout:kTimeout];

  LOG(INFO) << "Switching network again...";
  OCMExpect([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);
  OCMStub([_mockUDPSession
      setReadHandler:([OCMArg invokeBlockWithArgs:datagrams, [NSNull null], nil])
        maxDatagrams:64]);
  OCMExpect([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);
  XCTAssertTrue(_datapath->SwitchNetwork(1, endpoint, network_info, 1).ok());

  LOG(INFO) << "Stopping datapath...";
  _datapath->Stop();
}

@end
