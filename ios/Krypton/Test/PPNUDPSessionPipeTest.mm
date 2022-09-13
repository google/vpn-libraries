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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNUDPSessionPipe.h"

#import <XCTest/XCTest.h>

#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/Classes/NSObject+PPNKVO.h"
#import "third_party/absl/status/status.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

using ::privacy::krypton::IPProtocol;
using ::privacy::krypton::Packet;
using ::privacy::krypton::PPNUDPSessionPipe;

@interface PPNUDPSessionPipeTest : XCTestCase
@end

@implementation PPNUDPSessionPipeTest {
  id _mockUDPSession;
  PPNKVOHandler _handler;
}

- (void)setUp {
  [super setUp];
  _mockUDPSession = OCMClassMock([NWUDPSession class]);

  OCMStub([_mockUDPSession state]).andReturn(NWUDPSessionStateReady);

  OCMStub([_mockUDPSession setObserverHandler:[OCMArg any]])
      .andDo(^(NWUDPSession *, PPNKVOHandler handler) {
        _handler = handler;
      });

  OCMStub([_mockUDPSession cancel]).andDo(^(NWUDPSession *) {
    _handler(
        @"state", _mockUDPSession,
        @{@"new" : @(NWUDPSessionStateCancelled)}, nullptr);
  });

  OCMStub([_mockUDPSession removeObserverForKeyPath:@"state"]).andDo(^(NWUDPSession *, NSString *) {
    _handler = nil;
  });
}

- (void)testWritePacket {
  PPNUDPSessionPipe pipe(_mockUDPSession, ::privacy::krypton::IPProtocol::kIPv4);

  OCMStub([_mockUDPSession writeDatagram:[OCMArg any]
                       completionHandler:[OCMArg checkWithBlock:^(id obj) {
                         void (^handler)(NSError *_Nullable error) = obj;
                         handler(nil);
                         return YES;
                       }]]);

  // The packet's data is a string literal, so we don't need to free it.
  Packet packet("hello", 5, IPProtocol::kIPv4, []() {});
  std::vector<Packet> packets;
  packets.emplace_back(std::move(packet));
  auto status = pipe.WritePackets(std::move(packets));
  NSLog(@"Status: %s", status.ToString().c_str());
  XCTAssertTrue(status.ok());

  pipe.Close();
}

- (void)testWritePacketWithError {
  PPNUDPSessionPipe pipe(_mockUDPSession, ::privacy::krypton::IPProtocol::kIPv4);

  OCMStub([_mockUDPSession writeDatagram:[OCMArg any]
                       completionHandler:[OCMArg checkWithBlock:^(id obj) {
                         void (^handler)(NSError *_Nullable error) = obj;
                         handler([NSError errorWithDomain:PPNErrorDomain
                                                     code:PPNErrorDeadlineExceeded
                                                 userInfo:@{
                                                   NSLocalizedDescriptionKey : @"detailed message",
                                                 }]);
                         return YES;
                       }]]);

  // The packet's data is a string literal, so we don't need to free it.
  Packet packet("hello", 5, IPProtocol::kIPv4, []() {});
  std::vector<Packet> packets;
  packets.emplace_back(std::move(packet));
  auto status = pipe.WritePackets(std::move(packets));
  NSLog(@"Status: %s", status.ToString().c_str());
  // We just ignore write failures, because we can't block the thread waiting to see if it worked.
  XCTAssertTrue(status.ok());

  pipe.Close();
}

- (void)testReadPacket {
  privacy::krypton::PPNUDPSessionPipe pipe(_mockUDPSession, privacy::krypton::IPProtocol::kIPv6);

  // Capture the block that gets passed to ios as a handler.
  __block void (^innerBlock)(NSArray<NSData *> *datagrams, NSError *error);
  BOOL (^blockChecker)(id obj) = ^BOOL(id obj) {
    innerBlock = obj;
    return YES;
  };
  OCMStub([_mockUDPSession setReadHandler:[OCMArg checkWithBlock:blockChecker] maxDatagrams:1]);

  // Set up some specific expectations to expect.
  XCTestExpectation *expectationFoo6 = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationBar6 = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationBaz6 = [[XCTestExpectation alloc] init];
  NSArray<XCTestExpectation *> *expectations =
      @[ expectationFoo6, expectationBar6, expectationBaz6 ];

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status status, std::vector<Packet> packets) {
    if (!status.ok()) {
      return NO;
    }
    if (packets.size() != 1) {
      return NO;
    }
    auto packet = std::move(packets[0]);
    if (packet.data() == "foo" && packet.protocol() == IPProtocol::kIPv6) {
      [expectationFoo6 fulfill];
    }
    if (packet.data() == "bar" && packet.protocol() == IPProtocol::kIPv6) {
      [expectationBar6 fulfill];
    }
    if (packet.data() == "baz" && packet.protocol() == IPProtocol::kIPv6) {
      [expectationBaz6 fulfill];
    }
    return YES;
  });

  // Call the inner block.
  innerBlock(@[ [@"foo" dataUsingEncoding:NSUTF8StringEncoding] ], nil);
  innerBlock(@[ [@"bar" dataUsingEncoding:NSUTF8StringEncoding] ], nil);
  innerBlock(@[ [@"baz" dataUsingEncoding:NSUTF8StringEncoding] ], nil);

  // Now verify that calls to the inner block triggered the outer block.
  [self waitForExpectations:expectations timeout:5.0 enforceOrder:YES];

  pipe.Close();
}

- (void)testReadPacketWithError {
  privacy::krypton::PPNUDPSessionPipe pipe(_mockUDPSession, privacy::krypton::IPProtocol::kIPv6);

  // Capture the block that gets passed to ios as a handler.
  __block void (^innerBlock)(NSArray<NSData *> *datagrams, NSError *error);
  BOOL (^blockChecker)(id obj) = ^BOOL(id obj) {
    innerBlock = obj;
    return YES;
  };
  OCMStub([_mockUDPSession setReadHandler:[OCMArg checkWithBlock:blockChecker] maxDatagrams:1]);

  // Set up some specific expectations to expect.
  XCTestExpectation *expectationFoo6 = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationFailure = [[XCTestExpectation alloc] init];
  NSArray<XCTestExpectation *> *expectations = @[ expectationFoo6, expectationFailure ];

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status status, std::vector<Packet> packets) {
    if (status.code() == absl::StatusCode::kAlreadyExists) {
      [expectationFailure fulfill];
      return YES;
    }
    if (packets.size() != 1) {
      return NO;
    }
    auto packet = std::move(packets[0]);
    if (packet.data() == "foo" && packet.protocol() == IPProtocol::kIPv6) {
      [expectationFoo6 fulfill];
    }
    return YES;
  });

  // Call the inner block.
  innerBlock(@[ [@"foo" dataUsingEncoding:NSUTF8StringEncoding] ], nil);
  innerBlock(nil, [NSError errorWithDomain:PPNErrorDomain code:PPNErrorAlreadyExists userInfo:nil]);

  // Now verify that calls to the inner block triggered the outer block.
  [self waitForExpectations:expectations timeout:5.0 enforceOrder:YES];

  pipe.Close();
}

- (void)testReadPacketWithMultipleDatagrams {
  privacy::krypton::PPNUDPSessionPipe pipe(_mockUDPSession, privacy::krypton::IPProtocol::kIPv6);

  // Capture the block that gets passed to ios as a handler.
  __block void (^innerBlock)(NSArray<NSData *> *datagrams, NSError *error);
  BOOL (^blockChecker)(id obj) = ^BOOL(id obj) {
    innerBlock = obj;
    return YES;
  };
  OCMStub([_mockUDPSession setReadHandler:[OCMArg checkWithBlock:blockChecker] maxDatagrams:1]);

  // Set up some specific expectations to expect.
  XCTestExpectation *expectation = [[XCTestExpectation alloc] init];
  NSArray<XCTestExpectation *> *expectations = @[ expectation ];

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status status, std::vector<Packet> packets) {
    if (packets.size() != 2) {
      return NO;
    }
    if (packets[0].data() != "foo") {
      return NO;
    }
    if (packets[1].data() != "bar") {
      return NO;
    }
    [expectation fulfill];
    return YES;
  });

  // Call the inner block.
  NSData *datagram1 = [@"foo" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *datagram2 = [@"bar" dataUsingEncoding:NSUTF8StringEncoding];
  innerBlock(@[ datagram1, datagram2 ], nil);

  // Now verify that calls to the inner block triggered the outer block.
  [self waitForExpectations:expectations timeout:5.0 enforceOrder:YES];

  pipe.Close();
}

- (void)testReadHandlerCalledAfterClose {
  privacy::krypton::PPNUDPSessionPipe pipe(_mockUDPSession, privacy::krypton::IPProtocol::kIPv6);

  // Capture the block that gets passed to ios as a handler.
  __block void (^innerBlock)(NSArray<NSData *> *datagrams, NSError *error);
  BOOL (^blockChecker)(id obj) = ^BOOL(id obj) {
    innerBlock = obj;
    return YES;
  };
  OCMStub([_mockUDPSession setReadHandler:[OCMArg checkWithBlock:blockChecker] maxDatagrams:1]);

  // Set up some specific expectations to expect.
  BOOL gotPacket1 = NO;
  BOOL gotPacket2 = NO;

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status /*status*/, std::vector<Packet> packets) {
    if (packets.size() != 1) {
      return NO;
    }
    auto packet = std::move(packets[0]);
    if (packet.data() == "foo") {
      gotPacket1 = YES;
    }
    if (packet.data() == "bar") {
      gotPacket2 = YES;
    }
    return YES;
  });

  // Call the inner block.
  NSData *datagram1 = [@"foo" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *datagram2 = [@"bar" dataUsingEncoding:NSUTF8StringEncoding];

  innerBlock(@[ datagram1 ], nil);
  XCTAssertTrue(gotPacket1);
  XCTAssertFalse(gotPacket2);

  pipe.Close();

  innerBlock(@[ datagram2 ], nil);
  XCTAssertTrue(gotPacket1);
  XCTAssertFalse(gotPacket2);
}

- (void)testReadHandlerCalledAfterDestruction {
  auto pipe = std::make_unique<privacy::krypton::PPNUDPSessionPipe>(
      _mockUDPSession, privacy::krypton::IPProtocol::kIPv6);

  // Capture the block that gets passed to ios as a handler.
  __block void (^innerBlock)(NSArray<NSData *> *datagrams, NSError *error);
  BOOL (^blockChecker)(id obj) = ^BOOL(id obj) {
    innerBlock = obj;
    return YES;
  };
  OCMStub([_mockUDPSession setReadHandler:[OCMArg checkWithBlock:blockChecker] maxDatagrams:1]);

  // Set up some specific expectations to expect.
  BOOL gotPacket1 = NO;
  BOOL gotPacket2 = NO;

  // Set our own handler.
  pipe->ReadPackets([&](absl::Status /*status*/, std::vector<Packet> packets) {
    if (packets.size() != 1) {
      return NO;
    }
    auto packet = std::move(packets[0]);
    if (packet.data() == "foo") {
      gotPacket1 = YES;
    }
    if (packet.data() == "bar") {
      gotPacket2 = YES;
    }
    return YES;
  });

  // Call the inner block.
  NSData *datagram1 = [@"foo" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *datagram2 = [@"bar" dataUsingEncoding:NSUTF8StringEncoding];

  innerBlock(@[ datagram1 ], nil);
  XCTAssertTrue(gotPacket1);
  XCTAssertFalse(gotPacket2);

  pipe->Close();
  pipe = nullptr;

  innerBlock(@[ datagram2 ], nil);
  XCTAssertTrue(gotPacket1);
  XCTAssertFalse(gotPacket2);
}

@end
