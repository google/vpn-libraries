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

NS_ASSUME_NONNULL_BEGIN

/**
 * Methods used by the PPN library to update tunnel network settings, get packet flow, etc.
 */
@protocol PPNVirtualNetworkInterfaceManaging

/**
 * A NEPacketTunnelFlow object which is used to receive IP packets routed to
 * the tunnel's virtual interface and inject IP packets into the networking stack via
 * the tunnel's virtual interface.
 */
@property(readonly) NEPacketTunnelFlow *packetFlow;

/**
 * Updates the Packet Tunnel Provider with the network settings to be used to configure the TUN
 * interface and start the VPN tunnel.
 */
- (NSError *)updateTunnelNetworkSettings:(NEPacketTunnelNetworkSettings *)settings;

/**
 * See following documentation for details:
 * https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/1406055-createtcpconnectionthroughtunnel?language=objc
 */
- (NWTCPConnection *)createTCPConnectionThroughTunnelToEndpoint:(NWEndpoint *)remoteEndpoint
                                                      enableTLS:(BOOL)enableTLS
                                                  TLSParameters:
                                                      (nullable NWTLSParameters *)TLSParameters
                                                       delegate:(nullable id)delegate;

@end

NS_ASSUME_NONNULL_END
