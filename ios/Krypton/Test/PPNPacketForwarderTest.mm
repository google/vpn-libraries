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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketForwarder.h"

#import <XCTest/XCTest.h>

#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

// The length of encryption / decryption keys.
constexpr int kKeyLen = 32;

// How long to wait for test expectations.
constexpr NSTimeInterval kTimeout = 30.0;

// Aliases for block types, to make it easier to write mocks.
using PPNSessionReadHandler = void (^)(NSArray<NSData *> *_Nullable, NSError *_Nullable);
using PPNSessionWriteCompletion = void (^)(NSError *_Nullable);
using PPNTunnelReadCompletion = void (^)(NSArray<NEPacket *> *);

namespace privacy {
namespace krypton {

// A helper for testing notifications send from the forwarder.
class TestNotification : public PacketForwarderNotificationInterface {
 public:
  TestNotification() {}
  ~TestNotification() override {}

  // Returns an expectation that will be fulfilled once PacketForwarderFailed is called.
  XCTestExpectation *ExpectFailure() {
    return AddExpectation(@"PacketForwarderFailed", _failedExpectations);
  }

  XCTestExpectation *ExpectPermanentFailure() {
    return AddExpectation(@"PacketForwarderPermanentFailure", _permanentFailureExpectations);
  }

  XCTestExpectation *ExpectConnected() {
    return AddExpectation(@"PacketForwarderConnected", _connectedExpectations);
  }

  void PacketForwarderFailed(const absl::Status &) override {
    FulfillExpectation(@"PacketForwarderFailed", _failedExpectations);
  }

  void PacketForwarderPermanentFailure(const absl::Status &) override {
    FulfillExpectation(@"PacketForwarderPermanentFailure", _permanentFailureExpectations);
  }

  void PacketForwarderConnected() override {
    FulfillExpectation(@"PacketForwarderConnected", _connectedExpectations);
  }

  void PacketForwarderHasBetterPath(NWUDPSession *udp_session) override {}

  void VerifyNoMoreNotifications() {
    if (_unexpectedNotifications.count > 0) {
      XCTFail(@"Unexpected notifications: %@",
              [_unexpectedNotifications componentsJoinedByString:@", "]);
    }
  }

 private:
  XCTestExpectation *AddExpectation(NSString *name, NSMutableArray<XCTestExpectation *> *array) {
    XCTestExpectation *expectation = [[XCTestExpectation alloc] initWithDescription:name];
    [array addObject:expectation];
    return expectation;
  }

  void FulfillExpectation(NSString *name, NSMutableArray<XCTestExpectation *> *array) {
    LOG(INFO) << name.UTF8String;
    if (array.count < 1) {
      [_unexpectedNotifications addObject:name];
      return;
    }
    XCTestExpectation *expectation = array.firstObject;
    [array removeObjectAtIndex:0];
    [expectation fulfill];
  }

  NSMutableArray<XCTestExpectation *> *_failedExpectations = [NSMutableArray array];
  NSMutableArray<XCTestExpectation *> *_permanentFailureExpectations = [NSMutableArray array];
  NSMutableArray<XCTestExpectation *> *_connectedExpectations = [NSMutableArray array];
  NSMutableArray<NSString *> *_unexpectedNotifications = [NSMutableArray array];
};

}  // namespace krypton
}  // namespace privacy

// Internal methods exposed to make testing easier.
@interface PPNPacketForwarder (Tests)
- (void)startWithSessionReadyTimeout:(NSTimeInterval)sessionReadyTimeout
                 sessionWriteTimeout:(NSTimeInterval)sessionWriteTimeout;
- (void)observeStateChangedTo:(NWUDPSessionState)state;
@end

// Convenience methods for inspecting packets.
@interface NEPacket (Tests)
- (NSString *)dataString;
@end

@implementation NEPacket (Tests)

// Converts the data from the packet to a string.
- (NSString *)dataString {
  const char *data = reinterpret_cast<const char *>(self.data.bytes);
  size_t size = self.data.length;
  NSString *str = [[NSString alloc] initWithBytes:data length:size encoding:NSUTF8StringEncoding];
  return str;
}

@end

@interface PPNPacketForwarderTest : XCTestCase
@end

@implementation PPNPacketForwarderTest {
  // A packet forwarder instance to test.
  PPNPacketForwarder *_packetForwarder;

  // Mock objects for passing to the packet forwarder.
  id _packetTunnelFlow;
  id _session;
  privacy::krypton::TestNotification _notification;
  std::unique_ptr<privacy::krypton::utils::LooperThread> _notificationLooper;

  // Encryptor/decryptor to use to simulate the backend.
  std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecEncryptor> _backendEncryptor;
  std::unique_ptr<privacy::krypton::datapath::ipsec::IpSecDecryptor> _backendDecryptor;
}

- (void)setUp {
  [super setUp];

  // Create shared encryption keys.
  char uplink_key[kKeyLen + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
  char downlink_key[kKeyLen + 1] = "543210ZYXWVUTSRQPONMLKJIHGFEDCBA";
  char uplink_salt[5] = "C->B";
  char downlink_salt[5] = "B->C";

  // Set up the client encryptor/decryptor.
  uint32_t spi = 12;
  privacy::krypton::TransformParams params;
  auto ipsec = params.mutable_ipsec();
  ipsec->set_uplink_key(uplink_key);
  ipsec->set_downlink_key(downlink_key);
  ipsec->set_uplink_salt(uplink_salt);
  ipsec->set_downlink_salt(downlink_salt);
  auto clientEncryptor = privacy::krypton::datapath::ipsec::IpSecEncryptor::Create(spi, params);
  XCTAssertTrue(clientEncryptor.ok());
  auto clientDecryptor = privacy::krypton::datapath::ipsec::IpSecDecryptor::Create(params);
  XCTAssertTrue(clientDecryptor.ok());

  // Set up the backend encryptor/decryptor.
  // The keys and salt are the inverse of the client's.
  ipsec->set_uplink_key(downlink_key);
  ipsec->set_downlink_key(uplink_key);
  ipsec->set_uplink_salt(downlink_salt);
  ipsec->set_downlink_salt(uplink_salt);
  auto backendEncryptor = privacy::krypton::datapath::ipsec::IpSecEncryptor::Create(spi, params);
  XCTAssertTrue(backendEncryptor.ok());
  auto backendDecryptor = privacy::krypton::datapath::ipsec::IpSecDecryptor::Create(params);
  XCTAssertTrue(backendDecryptor.ok());
  _backendEncryptor = *std::move(backendEncryptor);
  _backendDecryptor = *std::move(backendDecryptor);

  // Set up the rest of the packet forwarder.
  privacy::krypton::KryptonConfig config;
  _packetTunnelFlow = OCMClassMock([NEPacketTunnelFlow class]);
  _session = OCMClassMock([NWUDPSession class]);
  OCMExpect([_session state]).andReturn(NWUDPSessionStatePreparing);
  _notificationLooper = std::make_unique<privacy::krypton::utils::LooperThread>("Test");
  _packetForwarder = [[PPNPacketForwarder alloc] initWithConfig:config
                                                      encryptor:*std::move(clientEncryptor)
                                                      decryptor:*std::move(clientDecryptor)
                                               packetTunnelFlow:_packetTunnelFlow
                                                        session:_session
                                                   notification:&_notification
                                             notificationLooper:_notificationLooper.get()];
}

- (void)tearDown {
  _notification.VerifyNoMoreNotifications();

  // Make sure to stop the looper before the notification object goes out of scope.
  _notificationLooper->Stop();
  _notificationLooper->Join();
  _notificationLooper = nullptr;

  // Releaase the forwarder so it won't reference the session before the session is dealloc'd.
  _packetForwarder = nil;

  [super tearDown];
}

// Encrypts a string of data the same way the backend would.
- (NSData *)backendEncryptedData:(NSString *)str {
  privacy::krypton::datapath::ipsec::IpSecPacket packet;
  absl::string_view bytes(str.UTF8String, str.length);
  auto status = _backendEncryptor->Encrypt(bytes, privacy::krypton::IPProtocol::kIPv4, &packet);
  XCTAssertTrue(status.ok());
  return [NSData dataWithBytes:packet.buffer() length:packet.buffer_size()];
}

// Decrypts data the way the backend would.
- (NSString *)backendDecryptedString:(NSData *)data {
  privacy::krypton::datapath::ipsec::IpSecPacket packet;
  absl::string_view bytes(reinterpret_cast<const char *>(data.bytes), data.length);
  privacy::krypton::IPProtocol protocol;
  auto status = _backendDecryptor->Decrypt(bytes, &packet, &protocol);
  XCTAssertTrue(status.ok());
  NSData *decrypted = [NSData dataWithBytes:packet.data() length:packet.data_size()];
  return [[NSString alloc] initWithBytes:decrypted.bytes
                                  length:decrypted.length
                                encoding:NSUTF8StringEncoding];
}

// Tests successful two-way traffic through the packet forwarder.
- (void)testUplinkAndDownlink {
  XCTestExpectation *uplinkComplete = [[XCTestExpectation alloc] initWithDescription:@"uplink"];
  XCTestExpectation *downlinkComplete = [[XCTestExpectation alloc] initWithDescription:@"downlink"];

  // Simulate receiving alpha, beta, gamma encrypted from the network.
  NSMutableArray<NSData *> *downlinkPackets = [NSMutableArray array];
  for (NSString *str in @[ @"alpha", @"beta", @"gamma" ]) {
    [downlinkPackets addObject:[self backendEncryptedData:str]];
  }
  OCMExpect([_session setReadHandler:OCMOCK_ANY maxDatagrams:64])
      .andDo(^(NWUDPSession *session, PPNSessionReadHandler readHandler, NSUInteger maxDatagrams) {
        LOG(INFO) << "Session read called.";
        readHandler(downlinkPackets, nil);
      });

  // Verify that alpha, beta, gamma are sent unencrypted to the tunnel.
  OCMExpect([_packetTunnelFlow writePacketObjects:OCMOCK_ANY])
      .andDo(^BOOL(NEPacketTunnelFlow *packetTunnelFlow, NSArray<NEPacket *> *packets) {
        LOG(INFO) << "Tunnel write called.";
        XCTAssertEqual(3u, packets.count);
        XCTAssertEqualObjects(@"alpha", [packets[0] dataString]);
        XCTAssertEqualObjects(@"beta", [packets[1] dataString]);
        XCTAssertEqualObjects(@"gamma", [packets[2] dataString]);
        [downlinkComplete fulfill];
        return YES;
      });

  // Simulate receiving foo, bar, baz unencrypted from the tunnel.
  NSMutableArray<NEPacket *> *uplinkPackets = [NSMutableArray array];
  for (NSString *str in @[ @"foo", @"bar", @"baz" ]) {
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NEPacket *packet = [[NEPacket alloc] initWithData:data protocolFamily:AF_INET];
    [uplinkPackets addObject:packet];
  }
  OCMExpect([_packetTunnelFlow readPacketObjectsWithCompletionHandler:OCMOCK_ANY])
      .andDo(^(NEPacketTunnelFlow *packetTunnelFlow, PPNTunnelReadCompletion callback) {
        LOG(INFO) << "Tunnel read called once.";
        callback(uplinkPackets);
      });
  OCMExpect([_packetTunnelFlow readPacketObjectsWithCompletionHandler:OCMOCK_ANY])
      .andDo(^(NEPacketTunnelFlow *packetTunnelFlow, PPNTunnelReadCompletion callback) {
        LOG(INFO) << "Tunnel read called twice.";
      });

  // Verify that foo, bar, baz are sent encrypted to the network.
  OCMExpect([_session writeMultipleDatagrams:OCMOCK_ANY completionHandler:OCMOCK_ANY])
      .andDo(^(NWUDPSession *session, NSArray<NSData *> *datagrams,
               PPNSessionWriteCompletion callback) {
        LOG(INFO) << "Session write called.";
        XCTAssertEqual(3u, datagrams.count);
        XCTAssertEqualObjects(@"foo", [self backendDecryptedString:datagrams[0]]);
        XCTAssertEqualObjects(@"bar", [self backendDecryptedString:datagrams[1]]);
        XCTAssertEqualObjects(@"baz", [self backendDecryptedString:datagrams[2]]);
        callback(nil);
        [uplinkComplete fulfill];
      });

  // Run the packet forwarder until it's processed all of the mocks.
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  XCTestExpectation *connected = _notification.ExpectConnected();
  [_packetForwarder start];
  [self waitForExpectations:@[ connected ] timeout:kTimeout];
  [self waitForExpectations:@[ uplinkComplete, downlinkComplete ] timeout:kTimeout];
  [_packetForwarder stop];
}

// Tests that the packet forwarder correctly handles failures when reading from the network.
- (void)testSessionReadFailure {
  // Simulate a network read failure.
  OCMExpect([_session setReadHandler:OCMOCK_ANY maxDatagrams:64])
      .andDo(^(NWUDPSession *session, PPNSessionReadHandler readHandler, NSUInteger maxDatagrams) {
        LOG(INFO) << "Session read called.";
        readHandler(nil, [NSError errorWithDomain:@"domain" code:-1 userInfo:nil]);
      });

  OCMExpect([_packetTunnelFlow readPacketObjectsWithCompletionHandler:OCMOCK_ANY])
      .andDo(^(NEPacketTunnelFlow *packetTunnelFlow, PPNTunnelReadCompletion callback) {
        LOG(INFO) << "Tunnel read called.";
      });

  // Run the packet forwarder until it's processed all of the mocks.
  XCTestExpectation *failure = _notification.ExpectFailure();
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  [_packetForwarder start];
  [self waitForExpectations:@[ failure ] timeout:kTimeout];
  [_packetForwarder stop];
}

// Tests that the packet forwarder correctly handles write failures to the network.
- (void)testNetworkWriteFailure {
  XCTestExpectation *uplinkComplete = [[XCTestExpectation alloc] initWithDescription:@"uplink"];

  OCMExpect([_session setReadHandler:OCMOCK_ANY maxDatagrams:64])
      .andDo(^(NWUDPSession *session, PPNSessionReadHandler readHandler, NSUInteger maxDatagrams) {
        LOG(INFO) << "Session read called.";
      });

  // Simulate receiving foo, bar, baz unencrypted from the tunnel.
  NSMutableArray<NEPacket *> *uplinkPackets = [NSMutableArray array];
  for (NSString *str in @[ @"foo", @"bar", @"baz" ]) {
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NEPacket *packet = [[NEPacket alloc] initWithData:data protocolFamily:AF_INET];
    [uplinkPackets addObject:packet];
  }
  OCMExpect([_packetTunnelFlow readPacketObjectsWithCompletionHandler:OCMOCK_ANY])
      .andDo(^(NEPacketTunnelFlow *packetTunnelFlow, PPNTunnelReadCompletion callback) {
        LOG(INFO) << "Tunnel read called once.";
        callback(uplinkPackets);
      });

  // Simulate the network failing.
  OCMExpect([_session writeMultipleDatagrams:OCMOCK_ANY completionHandler:OCMOCK_ANY])
      .andDo(^(NWUDPSession *session, NSArray<NSData *> *datagrams,
               PPNSessionWriteCompletion callback) {
        LOG(INFO) << "Session write called.";
        XCTAssertEqual(3u, datagrams.count);
        XCTAssertEqualObjects(@"foo", [self backendDecryptedString:datagrams[0]]);
        XCTAssertEqualObjects(@"bar", [self backendDecryptedString:datagrams[1]]);
        XCTAssertEqualObjects(@"baz", [self backendDecryptedString:datagrams[2]]);
        callback([NSError errorWithDomain:@"domain" code:-1 userInfo:nil]);
        [uplinkComplete fulfill];
      });

  // Run the packet forwarder until it's processed all of the mocks.
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  XCTestExpectation *failed = _notification.ExpectFailure();
  [_packetForwarder start];
  [self waitForExpectations:@[ failed ] timeout:kTimeout];
  [self waitForExpectations:@[ uplinkComplete ] timeout:kTimeout];
  [_packetForwarder stop];
}

// Tests that failing to write to the tunnel is ignored.
- (void)testTunnelWriteFailure {
  // Simulate receiving alpha, beta, gamma encrypted from the network.
  NSMutableArray<NSData *> *downlinkPackets = [NSMutableArray array];
  for (NSString *str in @[ @"alpha", @"beta", @"gamma" ]) {
    [downlinkPackets addObject:[self backendEncryptedData:str]];
  }
  XCTestExpectation *readHandlerComplete =
      [[XCTestExpectation alloc] initWithDescription:@"readHandlerComplete"];
  OCMExpect([_session setReadHandler:OCMOCK_ANY maxDatagrams:64])
      .andDo(^(NWUDPSession *session, PPNSessionReadHandler readHandler, NSUInteger maxDatagrams) {
        LOG(INFO) << "Session read called.";
        readHandler(downlinkPackets, nil);
        [readHandlerComplete fulfill];
      });

  // Verify that alpha, beta, gamma are sent unencrypted to the tunnel.
  // Then return that the wriite failed.
  OCMExpect([_packetTunnelFlow writePacketObjects:OCMOCK_ANY])
      .andDo(^BOOL(NEPacketTunnelFlow *packetTunnelFlow, NSArray<NEPacket *> *packets) {
        LOG(INFO) << "Tunnel write called.";
        XCTAssertEqual(3u, packets.count);
        XCTAssertEqualObjects(@"alpha", [packets[0] dataString]);
        XCTAssertEqualObjects(@"beta", [packets[1] dataString]);
        XCTAssertEqualObjects(@"gamma", [packets[2] dataString]);
        return NO;
      });

  // Run the packet forwarder until it's processed all of the mocks.
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  XCTestExpectation *connected = _notification.ExpectConnected();
  [_packetForwarder start];
  [self waitForExpectations:@[ connected ] timeout:kTimeout];
  [self waitForExpectations:@[ readHandlerComplete ] timeout:kTimeout];

  // Verify the error was counted.
  privacy::krypton::DatapathDebugInfo debugInfo;
  [_packetForwarder collectDebugInfo:&debugInfo];
  XCTAssertEqual(1, debugInfo.tunnel_write_errors());

  [_packetForwarder stop];
}

// Test that any packets that can't be decrypted are ignored.
- (void)testDecryptionErrorsIgnored {
  XCTestExpectation *downlinkComplete = [[XCTestExpectation alloc] initWithDescription:@"downlink"];

  // Simulate receiving alpha, beta, gamma encrypted from the network.
  // Add in a garbage packet that should be skipped.
  NSMutableArray<NSData *> *downlinkPackets = [NSMutableArray array];
  [downlinkPackets addObject:[@"some garbage" dataUsingEncoding:NSUTF8StringEncoding]];
  for (NSString *str in @[ @"alpha", @"beta", @"gamma" ]) {
    [downlinkPackets addObject:[self backendEncryptedData:str]];
  }
  OCMExpect([_session setReadHandler:OCMOCK_ANY maxDatagrams:64])
      .andDo(^(NWUDPSession *session, PPNSessionReadHandler readHandler, NSUInteger maxDatagrams) {
        LOG(INFO) << "Session read called.";
        readHandler(downlinkPackets, nil);
      });

  // Verify that alpha, beta, gamma are sent unencrypted to the tunnel.
  OCMExpect([_packetTunnelFlow writePacketObjects:OCMOCK_ANY])
      .andDo(^BOOL(NEPacketTunnelFlow *packetTunnelFlow, NSArray<NEPacket *> *packets) {
        LOG(INFO) << "Tunnel write called.";
        XCTAssertEqual(3u, packets.count);
        XCTAssertEqualObjects(@"alpha", [packets[0] dataString]);
        XCTAssertEqualObjects(@"beta", [packets[1] dataString]);
        XCTAssertEqualObjects(@"gamma", [packets[2] dataString]);
        [downlinkComplete fulfill];
        return YES;
      });

  // Run the packet forwarder until it's processed all of the mocks.
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  XCTestExpectation *connected = _notification.ExpectConnected();
  [_packetForwarder start];
  [self waitForExpectations:@[ connected ] timeout:kTimeout];
  [self waitForExpectations:@[ downlinkComplete ] timeout:kTimeout];
  [_packetForwarder stop];
}

// Test that the packet forwarder correctly reports a failure if the session never becomes ready.
- (void)testSessionReadyTimeout {
  XCTestExpectation *failed = _notification.ExpectFailure();
  [_packetForwarder startWithSessionReadyTimeout:0.05 sessionWriteTimeout:5.0];
  [self waitForExpectations:@[ failed ] timeout:kTimeout];
  [_packetForwarder stop];
}

// Test that the packet forwarder reports a failure if a network write takes too long.
- (void)testSessionWriteTimeout {
  XCTestExpectation *uplinkComplete = [[XCTestExpectation alloc] initWithDescription:@"uplink"];

  // Simulate receiving foo, bar, baz unencrypted from the tunnel.
  NSMutableArray<NEPacket *> *uplinkPackets = [NSMutableArray array];
  for (NSString *str in @[ @"foo", @"bar", @"baz" ]) {
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NEPacket *packet = [[NEPacket alloc] initWithData:data protocolFamily:AF_INET];
    [uplinkPackets addObject:packet];
  }
  OCMExpect([_packetTunnelFlow readPacketObjectsWithCompletionHandler:OCMOCK_ANY])
      .andDo(^(NEPacketTunnelFlow *packetTunnelFlow, PPNTunnelReadCompletion callback) {
        LOG(INFO) << "Tunnel read called once.";
        callback(uplinkPackets);
      });

  // Verify that foo, bar, baz are sent encrypted to the network.
  OCMExpect([_session writeMultipleDatagrams:OCMOCK_ANY completionHandler:OCMOCK_ANY])
      .andDo(^(NWUDPSession *session, NSArray<NSData *> *datagrams,
               PPNSessionWriteCompletion callback) {
        LOG(INFO) << "Session write called.";
        XCTAssertEqual(3u, datagrams.count);
        XCTAssertEqualObjects(@"foo", [self backendDecryptedString:datagrams[0]]);
        XCTAssertEqualObjects(@"bar", [self backendDecryptedString:datagrams[1]]);
        XCTAssertEqualObjects(@"baz", [self backendDecryptedString:datagrams[2]]);
        // Don't call the callback. Let the forwarder think the session never responded.
        [uplinkComplete fulfill];
      });

  // Run the packet forwarder until it's processed all of the mocks.
  [_packetForwarder observeStateChangedTo:NWUDPSessionStateReady];
  XCTestExpectation *failure = _notification.ExpectFailure();
  [_packetForwarder startWithSessionReadyTimeout:60.0 sessionWriteTimeout:0.05];
  [self waitForExpectations:@[ uplinkComplete ] timeout:kTimeout];
  [self waitForExpectations:@[ failure ] timeout:kTimeout];
  [_packetForwarder stop];
}

@end
