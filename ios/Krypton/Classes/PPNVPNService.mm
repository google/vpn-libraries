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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNVPNService.h"

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#include <utility>

#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNUDPSessionManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"
#import "googlemac/iPhone/Shared/PPN/Classes/NSObject+PPNKVO.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNDatapath.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNPacketTunnelPipe.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNSubnetMaskConverter.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNUDPSessionPipe.h"

#include "base/logging.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

static const NSTimeInterval kTestConnectionTimeout = 2.0;
/// Monitor that observes TCP connectivity changes to ensure client has successful established a
/// connection with the backend.
@interface PPNNWTCPConnectionMonitor : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithTCPConnection:(NWTCPConnection*)connection NS_DESIGNATED_INITIALIZER;

@end

@implementation PPNNWTCPConnectionMonitor {
  NWTCPConnection* _connection;
  BOOL _viable;
  // An NSCondition that guards and notifies when _viable changes.
  NSCondition* _viableCondition;
}

- (instancetype)initWithTCPConnection:(NWTCPConnection*)connection {
  self = [super init];
  if (self != nil) {
    _connection = connection;
    _viable = NO;
    _viableCondition = [[NSCondition alloc] init];

    PPNNWTCPConnectionMonitor* weakSelf = self;
    [_connection setObserverHandler:^(NSString* keyPath, id __unused object,
                                      NSDictionary<NSKeyValueChangeKey, id>* change,
                                      void* _Nullable context) {
      PPNNWTCPConnectionMonitor* strongSelf = weakSelf;
      if (strongSelf == nil) {
        return;
      }
      if ([keyPath isEqualToString:@"viable"]) {
        [strongSelf->_viableCondition lock];
        NSNumber* viableNumber = change[NSKeyValueChangeNewKey];
        strongSelf->_viable = [viableNumber boolValue];
        [strongSelf->_viableCondition signal];
        [strongSelf->_viableCondition unlock];
      }
    }];
    [_connection addObserverForKeyPath:@"viable"
                               options:NSKeyValueObservingOptionNew
                               context:nullptr];

    // Now that KVO is set up to catch changes, set the initial _state.
    [_viableCondition lock];
    _viable = _connection.viable;
    [_viableCondition unlock];
  }
  return self;
}

- (void)dealloc {
  [_connection removeObserverForKeyPath:@"viable"];
}

- (absl::Status)waitForReady {
  absl::Status status = absl::OkStatus();
  NSDate* timeout = [NSDate dateWithTimeIntervalSinceNow:kTestConnectionTimeout];
  [_viableCondition lock];
  while (!_viable) {
    if (![_viableCondition waitUntilDate:timeout]) {
      PPNLog(@"[%p] Timeout waiting for NWTCPConnection to become ready.", self);
      status = absl::DeadlineExceededError("Timeout waiting for NWTCPConnection to become ready.");
      [_connection cancel];
      break;
    }
  }
  [_viableCondition unlock];
  return status;
}

@end

namespace privacy {
namespace krypton {

DatapathInterface* PPNVPNService::BuildDatapath(const KryptonConfig& config,
                                                utils::LooperThread* looper,
                                                TimerManager* timer_manager) {
  if (config.use_objc_datapath()) {
    return new PPNDatapath(config, looper, this, timer_manager);
  }
  return new datapath::ipsec::IpSecDatapath(config, looper, this, timer_manager);
}

absl::Status PPNVPNService::CreateTunnel(const TunFdData& tun_fd_data) {
  // TODO: Whenever this method is called, there needs to be a way to update tunnel's
  // network settings.
  absl::MutexLock l(&mutex_);
  tun_fd_data_ = tun_fd_data;
  if (tunnel_ != nullptr) {
    LOG(WARNING) << "Old tunnel was not closed. Closing now.";
    tunnel_->Close();
  }
  tunnel_ = std::make_unique<PPNPacketTunnelPipe>(GetPacketTunnelFlow());
  return absl::OkStatus();
}

PacketPipe* PPNVPNService::GetTunnel() {
  absl::MutexLock l(&mutex_);
  return tunnel_.get();
}

NEPacketTunnelFlow* PPNVPNService::GetPacketTunnelFlow() {
  id<PPNVirtualNetworkInterfaceManaging> networkManager = networkManager_;
  if (networkManager == nil) {
    LOG(WARNING) << "nil networkManager when attempting to GetPacketTunnelFlow";
  }
  NEPacketTunnelFlow* packetFlow = networkManager.packetFlow;
  if (packetFlow == nil) {
    LOG(WARNING) << "nil packetFlow when attempting to GetPacketTunnelFlow";
  }
  return packetFlow;
}

void PPNVPNService::CloseTunnel() {
  absl::MutexLock l(&mutex_);
  if (tunnel_ == nullptr) {
    return;
  }
  tunnel_->Close();
  tunnel_.reset();
}

absl::StatusOr<std::unique_ptr<PacketPipe>> PPNVPNService::CreateNetworkPipe(
    const NetworkInfo& network_info, const Endpoint& endpoint) {
  PPN_ASSIGN_OR_RETURN(auto session, CreateUDPSession(network_info, endpoint));
  auto pipe = std::make_unique<PPNUDPSessionPipe>(session, endpoint.ip_protocol());
  PPN_RETURN_IF_ERROR(pipe->WaitForReady());
  return pipe;
}

absl::StatusOr<NWUDPSession*> PPNVPNService::CreateUDPSession(const NetworkInfo& network_info,
                                                              const Endpoint& endpoint) {
  TunFdData tun_fd_data;
  {
    absl::MutexLock l(&mutex_);
    tun_fd_data = tun_fd_data_;
  }

  NSString* address = [NSString stringWithUTF8String:endpoint.address().c_str()];
  NSString* port = [NSString stringWithFormat:@"%d", endpoint.port()];
  NWHostEndpoint* hostEndpoint = [NWHostEndpoint endpointWithHostname:address port:port];

  // TODO: Investigate how to deal with routes in the TunFdData.

  NSMutableArray<NSString*>* ipv4Addresses = [[NSMutableArray alloc] init];
  NSMutableArray<NSString*>* ipv4Masks = [[NSMutableArray alloc] init];
  NSMutableArray<NSString*>* ipv6Addresses = [[NSMutableArray alloc] init];
  NSMutableArray<NSNumber*>* ipv6PrefixLengths = [[NSMutableArray alloc] init];
  for (const TunFdData_IpRange& range : tun_fd_data.tunnel_ip_addresses()) {
    if (range.ip_family() == TunFdData::IpRange::IPV4) {
      [ipv4Addresses addObject:[NSString stringWithUTF8String:range.ip_range().c_str()]];

      if (range.prefix() <= 0 || range.prefix() > 32) {
        LOG(ERROR) << "Unexpected IpRange: " << range.DebugString();
        return absl::InvalidArgumentError("Unexpected IpRange");
      }
      [ipv4Masks addObject:PPNPrefixToIPv4SubnetMask(range.prefix())];
    }
    if (range.ip_family() == TunFdData::IpRange::IPV6) {
      [ipv6Addresses addObject:[NSString stringWithUTF8String:range.ip_range().c_str()]];
      [ipv6PrefixLengths addObject:@(range.prefix())];
    }
  }

  // Config NEIPv4Settings.
  NEIPv4Settings* ipv4Settings = [[NEIPv4Settings alloc] initWithAddresses:ipv4Addresses
                                                               subnetMasks:ipv4Masks];
  ipv4Settings.includedRoutes = @[ [NEIPv4Route defaultRoute] ];
  // See
  // https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  // for the list of these addresses.
  ipv4Settings.excludedRoutes = @[
    // IANA specifies that 0.0.0.0/8 should not be globally reachable.
    // However, for unknown reasons, if we specify 0.0.0.0/8 instead of 0.0.0.0/32,
    // the VPN icon doesn't show up on the status bar.
    [[NEIPv4Route alloc] initWithDestinationAddress:@"0.0.0.0" subnetMask:@"255.255.255.255"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"10.0.0.0" subnetMask:@"255.0.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"100.64.0.0" subnetMask:@"255.192.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"127.0.0.0" subnetMask:@"255.0.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"169.254.0.0" subnetMask:@"255.255.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"172.16.0.0" subnetMask:@"255.240.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"192.0.0.0" subnetMask:@"255.255.255.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"192.0.2.0" subnetMask:@"255.255.255.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"192.88.99.0" subnetMask:@"255.255.255.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"192.168.0.0" subnetMask:@"255.255.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"198.18.0.0" subnetMask:@"255.254.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"198.51.100.0" subnetMask:@"255.255.255.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"203.0.113.0" subnetMask:@"255.255.255.0"],
    // Only exclude the IP multicast address range that isn't routable.
    // See https://en.wikipedia.org/wiki/Multicast_address
    [[NEIPv4Route alloc] initWithDestinationAddress:@"224.0.0.0" subnetMask:@"255.255.255.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"239.255.255.250"
                                         subnetMask:@"255.255.255.255"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"240.0.0.0" subnetMask:@"240.0.0.0"],
    [[NEIPv4Route alloc] initWithDestinationAddress:@"255.255.255.255"
                                         subnetMask:@"255.255.255.255"]
  ];

  // Config NEIPv6Settings.
  NEIPv6Settings* ipv6Settings = [[NEIPv6Settings alloc] initWithAddresses:ipv6Addresses
                                                      networkPrefixLengths:ipv6PrefixLengths];
  ipv6Settings.includedRoutes = @[ [NEIPv6Route defaultRoute] ];
  // See
  // https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  // for the list of these addresses
  ipv6Settings.excludedRoutes = @[
    [[NEIPv6Route alloc] initWithDestinationAddress:@"::1" networkPrefixLength:@128],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"::ffff:0:0" networkPrefixLength:@96],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"64:ff9b:1::" networkPrefixLength:@48],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"100::" networkPrefixLength:@64],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"2001::" networkPrefixLength:@23],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"2001:2::" networkPrefixLength:@48],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"2001:db8::" networkPrefixLength:@32],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"2002::" networkPrefixLength:@16],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"fc00::" networkPrefixLength:@7],
    [[NEIPv6Route alloc] initWithDestinationAddress:@"fe80::" networkPrefixLength:@10],
    // We're excluding all IPv6 multicast addresses for now.
    [[NEIPv6Route alloc] initWithDestinationAddress:@"ff00::" networkPrefixLength:@8],
  ];

  // Config NEDNSSettings.
  NSMutableArray<NSString*>* dns = [[NSMutableArray alloc] init];
  for (const TunFdData_IpRange& range : tun_fd_data.tunnel_dns_addresses()) {
    [dns addObject:[NSString stringWithUTF8String:range.ip_range().c_str()]];
  }
  NEDNSSettings* dnsSettings = [[NEDNSSettings alloc] initWithServers:dns];

  // Config NEPacketTunnelNetworkSettings.
  NEPacketTunnelNetworkSettings* networkSettings =
      [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:address];
  networkSettings.DNSSettings = dnsSettings;
  networkSettings.IPv4Settings = ipv4Settings;
  networkSettings.IPv6Settings = ipv6Settings;
  networkSettings.MTU = @(tun_fd_data.mtu());

  PPNLog(@"Updating network settings with %@", networkSettings);

  NSError* error = [networkManager_ updateTunnelNetworkSettings:networkSettings];
  if (error != nullptr) {
    PPNLog(@"error updating the tunnel network settings: %@", error);
    return PPNStatusFromNSError(error);
  }

  // Setting fromEndpoint to nil means it's up to iOS to decide which port to use.
  PPNLog(@"Creating udp session to %@", hostEndpoint);
  auto* session = [UDPSessionManager_ createUDPSessionToEndpoint:hostEndpoint fromEndpoint:nil];
  return session;
}

absl::Status PPNVPNService::CheckConnection() {
  // TODO: Config host names with a parameter.
  auto endpoint = [NWHostEndpoint endpointWithHostname:@"www.google.com" port:@"80"];
  auto connection = [networkManager_ createTCPConnectionThroughTunnelToEndpoint:endpoint
                                                                      enableTLS:NO
                                                                  TLSParameters:nil
                                                                       delegate:nil];
  auto monitor = [[PPNNWTCPConnectionMonitor alloc] initWithTCPConnection:connection];
  return [monitor waitForReady];
}

}  // namespace krypton
}  // namespace privacy
