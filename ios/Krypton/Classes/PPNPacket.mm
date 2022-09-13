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

namespace privacy {
namespace krypton {

sa_family_t FamilyFromIPProtocol(IPProtocol protocol) {
  switch (protocol) {
    case IPProtocol::kIPv4:
      return AF_INET;
    case IPProtocol::kIPv6:
      return AF_INET6;
    default:
      return AF_UNSPEC;
  }
}

IPProtocol IPProtocolFromFamily(sa_family_t family) {
  switch (family) {
    case AF_INET:
      return IPProtocol::kIPv4;
    case AF_INET6:
      return IPProtocol::kIPv6;
    default:
      return IPProtocol::kUnknown;
  }
}

Packet PacketFromNSData(NSData *data, IPProtocol protocol) {
  // The cleanup lambda captures data by value, so that ARC will not release data until the cleanup
  // lambda has been destroyed, which will happen when this Packet is destroyed (or when another
  // Packet is assigned to this one using move semantics).
  return Packet(static_cast<const char *>(data.bytes), data.length, protocol, [data] {});  // NOLINT
}

Packet PacketFromNEPacket(NEPacket *packet) {
  return PacketFromNSData(packet.data, IPProtocolFromFamily(packet.protocolFamily));
}

NSData *NSDataFromPacketNoCopy(const Packet &packet) {
  return [NSData dataWithBytesNoCopy:const_cast<char *>(packet.data().data())
                              length:packet.data().length()
                        freeWhenDone:NO];
}

NEPacket *NEPacketFromPacketNoCopy(const Packet &packet) {
  NSData *data = NSDataFromPacketNoCopy(packet);
  sa_family_t protocol = FamilyFromIPProtocol(packet.protocol());
  return [[NEPacket alloc] initWithData:data protocolFamily:protocol];
}

}  // namespace krypton
}  // namespace privacy
