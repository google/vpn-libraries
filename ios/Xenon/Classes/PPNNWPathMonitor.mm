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

#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitor.h"
#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitorDelegate.h"

#import <Network/Network.h>

#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/utils/network_info.h"

@implementation PPNNWPathMonitor {
  nw_path_monitor_t _networkPathMonitor;
  std::optional<::privacy::krypton::NetworkInfo> _currentNetwork;
  BOOL _shouldRespectAllNetworkSwitches;
}

- (instancetype)initWithOptions:(NSDictionary<PPNOptionKey, id> *)options {
  self = [super init];
  if (self != nullptr) {
    _shouldRespectAllNetworkSwitches = _shouldRespectAllNetworkSwitches =
        [options[PPNRespectAllNetworkSwitches] isKindOfClass:[NSNumber class]] &&
        ((NSNumber *)options[PPNRespectAllNetworkSwitches]).boolValue;
  }
  return self;
}

- (void)startMonitor {
  // The IOS_MINIMUM_OS requirement to use this library is 12.0. iOS 11.4 will be dropped soon.
  if (@available(iOS 12.0, *)) {
    _currentNetwork = std::nullopt;
    _networkPathMonitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(_networkPathMonitor, dispatch_get_main_queue());
    PPNNWPathMonitor *__weak weakSelf = self;
    nw_path_monitor_set_update_handler(_networkPathMonitor, ^(nw_path_t path) {
      [weakSelf notifyPathChange:path];
    });
    nw_path_monitor_start(_networkPathMonitor);
  }
}

- (void)stopMonitor {
  // The IOS_MINIMUM_OS requirement to use this library is 12.0. iOS 11.4 will be dropped soon.
  if (@available(iOS 12.0, *)) {
    nw_path_monitor_cancel(_networkPathMonitor);
  }
}

// Populates the NetworkInfo proto based on the given path.
- (void)populateNetworkInfo:(::privacy::krypton::NetworkInfo *)networkInfo forPath:(nw_path_t)path {
  // The IOS_MINIMUM_OS requirement to use this library is 12.0. iOS 11.4 will be dropped soon.
  if (@available(iOS 12.0, *)) {
    networkInfo->Clear();

    // Populate interface type. Krypton don't enumerate all types, and we don't currently use this
    // field in krypton itself, so it's primarily for debugging purposes. If it's not one of the
    // known types, it's left as UNKNOWN.
    if (nw_path_uses_interface_type(path, nw_interface_type_wifi)) {
      networkInfo->set_network_type(::privacy::krypton::NetworkType::WIFI);
    } else if (nw_path_uses_interface_type(path, nw_interface_type_cellular)) {
      networkInfo->set_network_type(::privacy::krypton::NetworkType::CELLULAR);
    }

    // Check for support for IPv4 and/or IPv6.
    bool has_ipv4 = nw_path_has_ipv4(path);
    bool has_ipv6 = nw_path_has_ipv6(path);
    if (has_ipv4 && has_ipv6) {
      networkInfo->set_address_family(::privacy::krypton::NetworkInfo::V4V6);
    } else if (has_ipv4) {
      networkInfo->set_address_family(::privacy::krypton::NetworkInfo::V4);
    } else if (has_ipv6) {
      networkInfo->set_address_family(::privacy::krypton::NetworkInfo::V6);
    }
  }
}

// Returns whether the given network is different enough from the current network.
- (BOOL)isChangedNetwork:(const ::privacy::krypton::NetworkInfo &)newNetwork {
  if (!_currentNetwork) {
    return YES;
  }

  // If WiFi is added or removed, then we should try to reconnect.
  if (newNetwork.network_type() != _currentNetwork->network_type()) {
    return YES;
  }

  // As long as the new network supports a superset of the protocols of the old network, we don't
  // need to reconnect.
  if (newNetwork.address_family() != privacy::krypton::NetworkInfo::V4V6 &&
      newNetwork.address_family() != _currentNetwork->address_family()) {
    return YES;
  }

  return NO;
}

- (void)notifyPathChange:(nw_path_t)path {
  if (path == nullptr) {
    return;
  }

  [self logPath:path];

  nw_path_status_t status = nw_path_get_status(path);
  if (status != nw_path_status_satisfied) {
    // No network is available.
    if (!_currentNetwork || status == nw_path_status_satisfiable) {
      return;
    }

    LOG(INFO) << "Notifying Krypton that network is no longer available.";
    _currentNetwork = std::nullopt;
    [_delegate NWPathMonitorDidDetectNoNetwork:self];
    return;
  }

  // Fetch the info for the current network.
  ::privacy::krypton::NetworkInfo networkInfo;
  [self populateNetworkInfo:&networkInfo forPath:path];

  LOG(INFO) << "Found satisfied path: "
            << privacy::krypton::utils::NetworkInfoDebugString(networkInfo);

  // If it's sufficiently different, then tell Krypton to reconnect.
  BOOL isChangedNetwork = [self isChangedNetwork:networkInfo];
  if (isChangedNetwork || _shouldRespectAllNetworkSwitches) {
    auto message = !isChangedNetwork ? "Network has not changed significantly but reconnect anyway."
                                     : "Network is sufficiently different. Notifying Krypton.";
    LOG(INFO) << message;
    _currentNetwork = networkInfo;
    [_delegate NWPathMonitor:self didDetectNetwork:networkInfo];
  } else {
    LOG(INFO) << "Network has not changed significantly. Ignoring change.";
  }
}

- (void)logPath:(nw_path_t)path {
  __block NSString *output = [NSString stringWithFormat:@"Path changed: %@\n", path];

  nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
    uint32_t index = nw_interface_get_index(interface);
    NSString *name = @(nw_interface_get_name(interface));
    NSString *type;
    switch (nw_interface_get_type(interface)) {
      case nw_interface_type_wifi:
        type = @"wifi";
        break;
      case nw_interface_type_cellular:
        type = @"cellular";
        break;
      case nw_interface_type_wired:
        type = @"wired";
        break;
      case nw_interface_type_loopback:
        type = @"loopback";
        break;
      case nw_interface_type_other:
        type = @"other";
        break;
    }
    output = [output stringByAppendingFormat:@"  interface %d: %@ (%@)\n", index, name, type];
    return true;
  });

  if (@available(iOS 13.0, *)) {
    nw_path_enumerate_gateways(path, ^bool(nw_endpoint_t endpoint) {
      switch (nw_endpoint_get_type(endpoint)) {
        case nw_endpoint_type_invalid:
          output = [output stringByAppendingFormat:@"  endpoint: invalid\n"];
          break;
        case nw_endpoint_type_address: {
          char *address = nw_endpoint_copy_address_string(endpoint);
          char *port = nw_endpoint_copy_port_string(endpoint);
          output =
              [output stringByAppendingFormat:@"  endpoint: address<%@:%@>\n", @(address), @(port)];
          free(address);
          free(port);
        } break;
        case nw_endpoint_type_host:
          output = [output stringByAppendingFormat:@"  endpoint: host<%@:%d>\n",
                                                   @(nw_endpoint_get_hostname(endpoint)),
                                                   nw_endpoint_get_port(endpoint)];
          break;
        case nw_endpoint_type_bonjour_service:
          output = [output stringByAppendingFormat:@"  endpoint: bonjour<>\n"];
          break;
        case nw_endpoint_type_url:
          output = [output
              stringByAppendingFormat:@"  endpoint: url<%@>\n", @(nw_endpoint_get_url(endpoint))];
          break;
      }
      return true;
    });
  }

  LOG(INFO) << output.UTF8String;
}

@end
