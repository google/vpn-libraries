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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketTunnelPipe.h"

#import <XCTest/XCTest.h>

#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "third_party/absl/status/status.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

using ::privacy::krypton::IPProtocol;
using ::privacy::krypton::Packet;
using ::privacy::krypton::PPNPacketTunnelPipe;

@interface PPNPacketTunnelPipeTest : XCTestCase
@end

@implementation PPNPacketTunnelPipeTest {
  id _mockPacketTunnelFlow;
}

- (void)setUp {
  [super setUp];
  _mockPacketTunnelFlow = OCMClassMock([NEPacketTunnelFlow class]);
}

- (void)testWritePacket {
  PPNPacketTunnelPipe pipe(_mockPacketTunnelFlow);

  OCMStub([_mockPacketTunnelFlow writePacketObjects:[OCMArg any]]).andReturn(YES);

  // The packet's data is a string literal, so we don't need to free it.
  Packet packet("hello", 5, IPProtocol::kIPv4, []() {});
  std::vector<Packet> packets;
  packets.emplace_back(std::move(packet));
  auto status = pipe.WritePackets(std::move(packets));
  NSLog(@"Status: %s", status.ToString().c_str());
  XCTAssertTrue(status.ok());
}

- (void)testReadPacket {
  privacy::krypton::PPNPacketTunnelPipe pipe(_mockPacketTunnelFlow);

  // This array is processed from last to first and the order matches the `expectations` array's
  // order below.
  NSMutableArray<NSArray<NEPacket *> *> *packetsArray = [[NSMutableArray alloc] initWithArray:@[
    @[
      [self makePacketWithData:@"bar" protocol:AF_INET6],
      [self makePacketWithData:@"baz" protocol:AF_INET],
    ],
    @[ [self makePacketWithData:@"foo" protocol:AF_INET] ],
  ]];

  [OCMStub([_mockPacketTunnelFlow readPacketObjectsWithCompletionHandler:[OCMArg any]])
      andDo:^(__unused id mockObj, id completionHandler) {
        void (^innerBlock)(NSArray<NEPacket *> *packets) = completionHandler;
        NSArray<NEPacket *> *packets = packetsArray.lastObject;
        if (packets == nullptr) return;
        [packetsArray removeLastObject];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          innerBlock(packets);
        });
      }];

  // Set up some specific expectations to expect.
  XCTestExpectation *expectationFoo4 = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationBar6 = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationBaz4 = [[XCTestExpectation alloc] init];
  NSArray<XCTestExpectation *> *expectations =
      @[ expectationFoo4, expectationBar6, expectationBaz4 ];

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status status, std::vector<Packet> packets) {
    if (!status.ok()) {
      return NO;
    }
    for (auto &packet : packets) {
      if (packet.data() == "foo" && packet.protocol() == IPProtocol::kIPv4) {
        [expectationFoo4 fulfill];
      }
      if (packet.data() == "bar" && packet.protocol() == IPProtocol::kIPv6) {
        [expectationBar6 fulfill];
      }
      if (packet.data() == "baz" && packet.protocol() == IPProtocol::kIPv4) {
        [expectationBaz4 fulfill];
      }
    }
    return YES;
  });

  // Now verify that calls to the inner block triggered the outer block.
  [self waitForExpectations:expectations timeout:5.0 enforceOrder:YES];

  auto status = pipe.StopReadingPackets();
  XCTAssertTrue(status.ok());
}

- (void)testReadPacketStopsWhenHandlerReturnsNO {
  privacy::krypton::PPNPacketTunnelPipe pipe(_mockPacketTunnelFlow);

  // This array is processed from last to first.
  NSMutableArray<NSArray<NEPacket *> *> *packetsArray = [[NSMutableArray alloc] initWithArray:@[
    @[
      [self makePacketWithData:@"bar" protocol:AF_INET6],
      [self makePacketWithData:@"qaz" protocol:AF_INET],
    ],
    @[ [self makePacketWithData:@"foo" protocol:AF_INET] ],
    @[ [self makePacketWithData:@"baz" protocol:AF_INET] ],
  ]];

  [OCMStub([_mockPacketTunnelFlow readPacketObjectsWithCompletionHandler:[OCMArg any]])
      andDo:^(__unused id mockObj, id completionHandler) {
        void (^innerBlock)(NSArray<NEPacket *> *packets) = completionHandler;
        NSArray<NEPacket *> *packets = packetsArray.lastObject;
        if (packets == nullptr) return;
        [packetsArray removeLastObject];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          innerBlock(packets);
        });
      }];

  // Set up some specific expectations to expect.
  XCTestExpectation *expectationFoo = [[XCTestExpectation alloc] init];
  XCTestExpectation *expectationBaz = [[XCTestExpectation alloc] init];
  NSArray<XCTestExpectation *> *expectations = @[ expectationBaz, expectationFoo ];

  // Set our own handler.
  pipe.ReadPackets([&](absl::Status status, std::vector<Packet> packets) {
    if (!status.ok()) {
      return NO;
    }
    if (packets.size() != 1) {
      return NO;
    }
    auto packet = std::move(packets[0]);
    if (packet.data() == "baz" && packet.protocol() == IPProtocol::kIPv4) {
      [expectationBaz fulfill];
    } else if (packet.data() == "foo" && packet.protocol() == IPProtocol::kIPv4) {
      [expectationFoo fulfill];
      return NO;
    } else {
      XCTAssert(NO, "Unexpected packets");
    }
    return YES;
  });

  [self waitForExpectations:expectations timeout:5.0 enforceOrder:YES];

  auto status = pipe.StopReadingPackets();
  XCTAssertTrue(status.ok());
}

- (void)testWritingToOldHandlerDoesNotHappen {
  privacy::krypton::PPNPacketTunnelPipe pipe(_mockPacketTunnelFlow);

  // Start reading with one handler and hang onto it.
  NSMutableArray<void (^)(NSArray<NEPacket *> *)> *handlers = [NSMutableArray array];
  [OCMStub([_mockPacketTunnelFlow readPacketObjectsWithCompletionHandler:[OCMArg any]])
      andDo:^(__unused id mockObj, id completionHandler) {
        [handlers addObject:completionHandler];
      }];
  BOOL handler1Called = NO;
  pipe.ReadPackets([&](absl::Status, std::vector<Packet>) {
    handler1Called = YES;
    return NO;
  });
  XCTAssertEqual(1ul, handlers.count);

  // Stop the pipe.
  XCTAssertTrue(pipe.StopReadingPackets().ok());

  // Start reading again with a different handler.
  pipe.ReadPackets([&](absl::Status, std::vector<Packet>) { return NO; });
  XCTAssertEqual(2ul, handlers.count);

  // If iOS calls the old handler, we want to make sure that the packet pipe ignores it.
  handlers.firstObject(@[ [self makePacketWithData:@"bar" protocol:AF_INET6] ]);

  XCTAssertFalse(handler1Called);
}

#pragma mark - Helper Method

- (NEPacket *)makePacketWithData:(NSString *)str protocol:(sa_family_t)protocol {
  NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
  return [[NEPacket alloc] initWithData:data protocolFamily:protocol];
}

@end
