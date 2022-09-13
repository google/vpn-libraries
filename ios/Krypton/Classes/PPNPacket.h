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

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#include "privacy/net/krypton/pal/packet.h"

NS_ASSUME_NONNULL_BEGIN

namespace privacy {
namespace krypton {

// Converts a krypton IP protocol into an iOS protocol.
sa_family_t FamilyFromIPProtocol(IPProtocol protocol);

// Converts an iOS protocol to a krypton IP protocol.
IPProtocol IPProtocolFromFamily(sa_family_t family);

/**
 * Constructs a krypton Packet from the given @c data and @c protocol. The
 * packet retains the NSData, so its data will be valid exactly as long as the
 * NSData's data is valid.
 */
Packet PacketFromNSData(NSData *data, IPProtocol protocol);

/**
 * Constructs a krypton Packet from an NEPacket*, taking a reference to the
 * underlying NSData, so that if the NSData is responsible for freeing the data,
 * the returned krypton Packet will keep it around.
 */
Packet PacketFromNEPacket(NEPacket *packet);

/**
 * Constructs an NSData from a @c packet that doesn't copy it, retain it, or try
 * to free it. The valid lifetime of the returned NSData is the same as the data
 * for the @c packet passed in.
 */
NSData *NSDataFromPacketNoCopy(const Packet &packet);

/**
 * Constructs an NEPacket from a krypton Packet without copying its data. The
 * NEPacket's data will only be valid as long as the Packet's data is.
 */
NEPacket *NEPacketFromPacketNoCopy(const Packet &packet);

}  // namespace krypton
}  // namespace privacy

NS_ASSUME_NONNULL_END
