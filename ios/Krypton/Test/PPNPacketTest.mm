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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacket.h"

#import <XCTest/XCTest.h>

@interface PPNPacketTest : XCTestCase
@end

@implementation PPNPacketTest

- (void)testPacketFromNSNEPacket {
  ::privacy::krypton::Packet packet;
  {
    // Make an NSData that owns its own data.
    NSData *data = [NSData dataWithBytes:"foo" length:3];
    NEPacket *nePacket = [[NEPacket alloc] initWithData:data protocolFamily:AF_INET];
    packet = ::privacy::krypton::PacketFromNEPacket(nePacket);
  }

  // Convert back to an NSData just to make using the expectation macro easier.
  NSData *actualData = ::privacy::krypton::NEPacketFromPacketNoCopy(packet).data;
  NSData *expectedData = [NSData dataWithBytes:"foo" length:3];

  XCTAssertEqualObjects(expectedData, actualData);
  XCTAssertEqual(::privacy::krypton::IPProtocol::kIPv4, packet.protocol());
}

- (void)testPacketDataGetsRetained {
  __weak NSData *weakData;
  {
    ::privacy::krypton::Packet packet;
    {
      @autoreleasepool {
        NSData *strongData = [NSData dataWithBytes:"foo" length:3];
        NEPacket *tempPacket = [[NEPacket alloc] initWithData:strongData protocolFamily:AF_INET];
        packet = ::privacy::krypton::PacketFromNEPacket(tempPacket);
        weakData = strongData;
      }
    }
    // Now, packet is alive, but the other strong references to data are not.
    XCTAssertNotNil(weakData);
  }
  // And now the packet is gone too.
  XCTAssertNil(weakData);
}

@end
