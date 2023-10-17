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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNProtoUtils.h"

NSDictionary<NSString *, id> *PPNKryptonDebugInfoToNSDictionary(
    const privacy::krypton::KryptonDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *debugInfoDictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_config()) {
    debugInfoDictionary[@"krypton_config"] = PPNKryptonConfigToNSDictionary(debugInfo.config());
  }
  if (debugInfo.has_cancelled()) {
    debugInfoDictionary[@"cancelled"] = @(debugInfo.cancelled());
  }
  if (debugInfo.has_reconnector()) {
    debugInfoDictionary[@"reconnector"] =
        PPNReconnectorDebugInfoToNSDictionary(debugInfo.reconnector());
  }
  if (debugInfo.has_auth()) {
    debugInfoDictionary[@"auth"] = PPNAuthDebugInfoToNSDictionary(debugInfo.auth());
  }
  if (debugInfo.has_egress()) {
    debugInfoDictionary[@"egress"] = PPNEgressDebugInfoToNSDictionary(debugInfo.egress());
  }
  if (debugInfo.has_session()) {
    debugInfoDictionary[@"session"] = PPNSessionDebugInfoToNSDictionary(debugInfo.session());
  }
  return debugInfoDictionary;
}

NSDictionary<NSString *, id> *PPNKryptonConfigToNSDictionary(
    const privacy::krypton::KryptonConfig &config) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  dictionary[@"zinc_url"] = [NSString stringWithCString:config.zinc_url().c_str()
                                               encoding:NSUTF8StringEncoding];
  dictionary[@"zinc_public_signing_key_url"] =
      [NSString stringWithCString:config.zinc_public_signing_key_url().c_str()
                         encoding:NSUTF8StringEncoding];
  dictionary[@"brass_url"] = [NSString stringWithCString:config.brass_url().c_str()
                                                encoding:NSUTF8StringEncoding];
  dictionary[@"initial_data_url"] = [NSString stringWithCString:config.initial_data_url().c_str()
                                                       encoding:NSUTF8StringEncoding];
  dictionary[@"service_type"] = [NSString stringWithCString:config.service_type().c_str()
                                                   encoding:NSUTF8StringEncoding];
  dictionary[@"reconnector_config"] =
      PPNReconnectorConfigToNSDictionary(config.reconnector_config());
  dictionary[@"copper_controller_address"] =
      [NSString stringWithCString:config.copper_controller_address().c_str()
                         encoding:NSUTF8StringEncoding];
  dictionary[@"copper_hostname_override"] =
      [NSString stringWithCString:config.copper_hostname_override().c_str()
                         encoding:NSUTF8StringEncoding];
  dictionary[@"api_key"] = [NSString stringWithCString:config.api_key().c_str()
                                              encoding:NSUTF8StringEncoding];

  NSMutableArray<NSString *> *array = [[NSMutableArray alloc] init];
  for (const std::string &suffix : config.copper_hostname_suffix()) {
    [array addObject:[NSString stringWithCString:suffix.c_str() encoding:NSUTF8StringEncoding]];
  }
  dictionary[@"copper_hostname_suffix"] = array;

  dictionary[@"cipher_suite_key_length"] = @(config.cipher_suite_key_length());
  dictionary[@"rekey_duration"] = @(PPNDurationToNSTimeInterval(config.rekey_duration()));
  dictionary[@"enable_blind_signing"] = @(config.enable_blind_signing());
  dictionary[@"safe_disconnect_enabled"] = @(config.safe_disconnect_enabled());
  dictionary[@"public_metadata_enabled"] = @(config.public_metadata_enabled());

  switch (config.datapath_protocol()) {
    case privacy::krypton::KryptonConfig::DEFAULT:
      dictionary[@"datapath_protocol"] = @"Default";
      break;
    case privacy::krypton::KryptonConfig::IPSEC:
      dictionary[@"datapath_protocol"] = @"IPSec";
      break;
    case privacy::krypton::KryptonConfig::BRIDGE:
      dictionary[@"datapath_protocol"] = @"Bridge";
      break;
    case privacy::krypton::KryptonConfig::IKE:
      dictionary[@"datapath_protocol"] = @"IKE";
      break;
  }

  dictionary[@"ipv6_enabled"] = @(config.ipv6_enabled());

  dictionary[@"use_objc_datapath"] = @(config.use_objc_datapath());

  dictionary[@"ip_geo_level"] = @(config.ip_geo_level());

  return dictionary;
}

NSDictionary<NSString *, id> *PPNReconnectorConfigToNSDictionary(
    const privacy::krypton::ReconnectorConfig &config) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (config.has_initial_time_to_reconnect_msec()) {
    dictionary[@"initial_time_to_reconnect_msec"] = @(config.initial_time_to_reconnect_msec());
  }
  if (config.has_session_connection_deadline_msec()) {
    dictionary[@"session_connection_deadline_msec"] = @(config.session_connection_deadline_msec());
  }
  return dictionary;
}

NSDictionary<NSString *, id> *PPNReconnectorDebugInfoToNSDictionary(
    const privacy::krypton::ReconnectorDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_state()) {
    dictionary[@"state"] = [NSString stringWithCString:debugInfo.state().c_str()
                                              encoding:NSUTF8StringEncoding];
  }
  if (debugInfo.has_session_restart_counter()) {
    dictionary[@"session_restart_counter"] = @(debugInfo.session_restart_counter());
  }
  if (debugInfo.has_successive_control_plane_failures()) {
    dictionary[@"successive_control_plane_failures"] =
        @(debugInfo.successive_control_plane_failures());
  }
  if (debugInfo.has_successive_data_plane_failures()) {
    dictionary[@"successive_data_plane_failures"] = @(debugInfo.successive_data_plane_failures());
  }
  return dictionary;
}

NSDictionary<NSString *, id> *PPNAuthDebugInfoToNSDictionary(
    const privacy::krypton::AuthDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_state()) {
    dictionary[@"state"] = [NSString stringWithCString:debugInfo.state().c_str()
                                              encoding:NSUTF8StringEncoding];
  }
  if (debugInfo.has_status()) {
    dictionary[@"status"] = [NSString stringWithCString:debugInfo.status().c_str()
                                               encoding:NSUTF8StringEncoding];
  }
  NSMutableArray<NSNumber *> *array = [[NSMutableArray alloc] init];
  for (const ::google::protobuf::Duration &duration : debugInfo.latency()) {
    [array addObject:@(PPNDurationToNSTimeInterval(duration))];
  }
  dictionary[@"latency"] = array;
  return dictionary;
}

NSDictionary<NSString *, id> *PPNEgressDebugInfoToNSDictionary(
    const privacy::krypton::EgressDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_state()) {
    dictionary[@"state"] = [NSString stringWithCString:debugInfo.state().c_str()
                                              encoding:NSUTF8StringEncoding];
  }
  if (debugInfo.has_status()) {
    dictionary[@"status"] = [NSString stringWithCString:debugInfo.status().c_str()
                                               encoding:NSUTF8StringEncoding];
  }
  NSMutableArray<NSNumber *> *array = [[NSMutableArray alloc] init];
  for (const ::google::protobuf::Duration &duration : debugInfo.latency()) {
    [array addObject:@(PPNDurationToNSTimeInterval(duration))];
  }
  dictionary[@"latency"] = array;
  return dictionary;
}

NSDictionary<NSString *, id> *PPNPacketPipeDebugInfoToNSDictionary(
    const privacy::krypton::PacketPipeDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_writes_started()) {
    dictionary[@"writes_started"] = @(debugInfo.writes_started());
  }
  if (debugInfo.has_writes_completed()) {
    dictionary[@"writes_completed"] = @(debugInfo.writes_completed());
  }
  if (debugInfo.has_write_errors()) {
    dictionary[@"write_errors"] = @(debugInfo.write_errors());
  }
  return dictionary;
}

NSDictionary<NSString *, id> *PPNDatapathDebugInfoToNSDictionary(
    const privacy::krypton::DatapathDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_uplink_packets_read()) {
    dictionary[@"uplink_packets_read"] = @(debugInfo.uplink_packets_read());
  }
  if (debugInfo.has_downlink_packets_read()) {
    dictionary[@"downlink_packets_read"] = @(debugInfo.downlink_packets_read());
  }
  if (debugInfo.has_uplink_packets_dropped()) {
    dictionary[@"uplink_packets_dropped"] = @(debugInfo.uplink_packets_dropped());
  }
  if (debugInfo.has_downlink_packets_dropped()) {
    dictionary[@"downlink_packets_dropped"] = @(debugInfo.downlink_packets_dropped());
  }
  if (debugInfo.has_decryption_errors()) {
    dictionary[@"decryption_errors"] = @(debugInfo.decryption_errors());
  }
  if (debugInfo.has_tunnel_write_errors()) {
    dictionary[@"tunnel_write_errors"] = @(debugInfo.tunnel_write_errors());
  }
  if (debugInfo.has_network_pipe()) {
    dictionary[@"network_pipe"] = PPNPacketPipeDebugInfoToNSDictionary(debugInfo.network_pipe());
  }
  if (debugInfo.has_device_pipe()) {
    dictionary[@"device_pipe"] = PPNPacketPipeDebugInfoToNSDictionary(debugInfo.device_pipe());
  }
  return dictionary;
}

NSDictionary<NSString *, id> *PPNSessionDebugInfoToNSDictionary(
    const privacy::krypton::SessionDebugInfo &debugInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (debugInfo.has_state()) {
    dictionary[@"state"] = [NSString stringWithCString:debugInfo.state().c_str()
                                              encoding:NSUTF8StringEncoding];
  }
  if (debugInfo.has_status()) {
    dictionary[@"status"] = [NSString stringWithCString:debugInfo.status().c_str()
                                               encoding:NSUTF8StringEncoding];
  }
  if (debugInfo.has_active_tun_fd()) {
    dictionary[@"active_tun_fd"] = @(debugInfo.active_tun_fd());
  }
  if (debugInfo.has_active_network()) {
    dictionary[@"active_network"] = PPNNetworkInfoToNSDictionary(debugInfo.active_network());
  }
  if (debugInfo.has_previous_tun_fd()) {
    dictionary[@"previous_tun_fd"] = @(debugInfo.previous_tun_fd());
  }
  if (debugInfo.has_previous_network()) {
    dictionary[@"previous_network"] = PPNNetworkInfoToNSDictionary(debugInfo.previous_network());
  }
  if (debugInfo.has_successful_rekeys()) {
    dictionary[@"successful_rekeys"] = @(debugInfo.successful_rekeys());
  }
  if (debugInfo.has_network_switches()) {
    dictionary[@"network_switches"] = @(debugInfo.network_switches());
  }
  if (debugInfo.has_datapath()) {
    dictionary[@"datapath"] = PPNDatapathDebugInfoToNSDictionary(debugInfo.datapath());
  }
  return dictionary;
}

NSDictionary<NSString *, id> *PPNNetworkInfoToNSDictionary(
    const privacy::krypton::NetworkInfo &networkInfo) {
  NSMutableDictionary<NSString *, id> *dictionary = [[NSMutableDictionary alloc] init];
  if (networkInfo.has_network_type()) {
    switch (networkInfo.network_type()) {
      case privacy::krypton::NetworkType::WIFI:
        dictionary[@"network_type"] = @"WIFI";
        break;
      case privacy::krypton::NetworkType::CELLULAR:
        dictionary[@"network_type"] = @"CELLULAR";
        break;
      default:
        dictionary[@"network_type"] = @"UNKNOWN";
        break;
    }
  }

  if (networkInfo.has_address_family()) {
    switch (networkInfo.address_family()) {
      case privacy::krypton::NetworkInfo::V4:
        dictionary[@"address_family"] = @"V4";
        break;
      case privacy::krypton::NetworkInfo::V6:
        dictionary[@"address_family"] = @"V6";
        break;
      case privacy::krypton::NetworkInfo::V4V6:
        dictionary[@"address_family"] = @"V4V6";
        break;
    }
  }

  if (networkInfo.has_is_metered()) {
    dictionary[@"is_metered"] = @(networkInfo.is_metered());
  }
  if (networkInfo.has_mtu()) {
    dictionary[@"mtu"] = @(networkInfo.mtu());
  }
  if (networkInfo.has_network_id()) {
    dictionary[@"network_id"] = @(networkInfo.network_id());
  }

  return dictionary;
}
