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

#import <XCTest/XCTest.h>

#include <string>

#import "googlemac/iPhone/Shared/PPN/Classes/PPNProtoUtils.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"

@interface PPNProtoUtilsTest : XCTestCase
@end

@implementation PPNProtoUtilsTest

- (void)testPPNKryptonDebugInfoToNSDictionary {
  privacy::krypton::KryptonConfig kryptonConfig;
  kryptonConfig.set_zinc_url("zinc_url");
  kryptonConfig.add_copper_hostname_suffix("foo");
  kryptonConfig.set_datapath_protocol(privacy::krypton::KryptonConfig::IPSEC);

  privacy::krypton::ReconnectorDebugInfo reconnectorDebugInfo;
  reconnectorDebugInfo.set_session_restart_counter(1);
  reconnectorDebugInfo.set_successive_control_plane_failures(1);
  reconnectorDebugInfo.set_successive_data_plane_failures(1);
  reconnectorDebugInfo.set_state("state");

  privacy::krypton::AuthDebugInfo authDebugInfo;
  authDebugInfo.set_state("foo");
  authDebugInfo.set_status("bar");

  privacy::krypton::EgressDebugInfo egressDebugInfo;
  egressDebugInfo.set_state("foo");
  egressDebugInfo.set_status("bar");

  privacy::krypton::PacketPipeDebugInfo pipeDebugInfo;
  pipeDebugInfo.set_writes_started(1);
  pipeDebugInfo.set_writes_completed(1);
  pipeDebugInfo.set_write_errors(1);

  privacy::krypton::DatapathDebugInfo datapathDebugInfo;
  datapathDebugInfo.set_uplink_packets_read(1);
  datapathDebugInfo.set_downlink_packets_read(2);
  datapathDebugInfo.set_uplink_packets_dropped(3);
  datapathDebugInfo.set_downlink_packets_dropped(4);
  datapathDebugInfo.set_decryption_errors(5);
  datapathDebugInfo.set_tunnel_write_errors(6);
  *datapathDebugInfo.mutable_network_pipe() = pipeDebugInfo;
  *datapathDebugInfo.mutable_device_pipe() = pipeDebugInfo;

  ::privacy::krypton::NetworkInfo network;
  network.set_network_type(privacy::krypton::NetworkType::WIFI);

  ::privacy::krypton::NetworkInfo previousNetwork;
  previousNetwork.set_network_type(privacy::krypton::NetworkType::CELLULAR);

  privacy::krypton::SessionDebugInfo sessionDebugInfo;
  sessionDebugInfo.set_state("foo");
  sessionDebugInfo.set_status("bar");
  sessionDebugInfo.set_active_tun_fd(1);
  sessionDebugInfo.set_previous_tun_fd(2);
  sessionDebugInfo.set_successful_rekeys(3);
  sessionDebugInfo.set_network_switches(4);
  *sessionDebugInfo.mutable_active_network() = network;
  *sessionDebugInfo.mutable_previous_network() = previousNetwork;
  *sessionDebugInfo.mutable_datapath() = datapathDebugInfo;

  privacy::krypton::KryptonDebugInfo debugInfo;
  debugInfo.set_cancelled(true);
  *debugInfo.mutable_config() = kryptonConfig;
  *debugInfo.mutable_reconnector() = reconnectorDebugInfo;
  *debugInfo.mutable_auth() = authDebugInfo;
  *debugInfo.mutable_egress() = egressDebugInfo;
  *debugInfo.mutable_session() = sessionDebugInfo;

  NSDictionary<NSString *, id> *expectedDictionary = @{
    @"krypton_config" : @{
      @"brass_url" : @"",
      @"cipher_suite_key_length" : @256,
      @"copper_controller_address" : @"",
      @"copper_hostname_override" : @"",
      @"copper_hostname_suffix" : @[ @"foo" ],
      @"datapath_protocol" : @"IPSec",
      @"enable_blind_signing" : @1,
      @"ipv6_enabled" : @1,
      @"reconnector_config" : @{},
      @"rekey_duration" : @0,
      @"safe_disconnect_enabled" : @0,
      @"service_type" : @"",
      @"use_objc_datapath" : @1,
      @"zinc_public_signing_key_url" : @"",
      @"zinc_url" : @"zinc_url",
    },
    @"cancelled" : @1,
    @"reconnector" : @{
      @"state" : @"state",
      @"session_restart_counter" : @1,
      @"successive_control_plane_failures" : @1,
      @"successive_data_plane_failures" : @1,
    },
    @"auth" : @{
      @"state" : @"foo",
      @"status" : @"bar",
      @"latency" : @[],
    },
    @"egress" : @{
      @"state" : @"foo",
      @"status" : @"bar",
      @"latency" : @[],
    },
    @"session" : @{
      @"state" : @"foo",
      @"status" : @"bar",
      @"active_tun_fd" : @1,
      @"previous_tun_fd" : @2,
      @"active_network" : @{
        @"network_type" : @"WIFI",
      },
      @"previous_network" : @{
        @"network_type" : @"CELLULAR",
      },
      @"successful_rekeys" : @3,
      @"network_switches" : @4,
      @"datapath" : @{
        @"uplink_packets_read" : @1,
        @"downlink_packets_read" : @2,
        @"uplink_packets_dropped" : @3,
        @"downlink_packets_dropped" : @4,
        @"decryption_errors" : @5,
        @"tunnel_write_errors" : @6,
        @"network_pipe" : @{
          @"writes_started" : @1,
          @"writes_completed" : @1,
          @"write_errors" : @1,
        },
        @"device_pipe" : @{
          @"writes_started" : @1,
          @"writes_completed" : @1,
          @"write_errors" : @1,
        },
      },
    },
  };

  NSDictionary<NSString *, id> *debugInfoDictionary = PPNKryptonDebugInfoToNSDictionary(debugInfo);
  XCTAssertEqualObjects(debugInfoDictionary, expectedDictionary);
}

- (void)testPPNReconnectorConfigToNSDictionary {
  privacy::krypton::ReconnectorConfig reconnectorConfig;
  reconnectorConfig.set_initial_time_to_reconnect_msec(1);
  reconnectorConfig.set_session_connection_deadline_msec(2);
  reconnectorConfig.set_datapath_watchdog_timer_msec(3);

  NSDictionary<NSString *, id> *expectedDictionary = @{
    @"datapath_watchdog_timer_msec" : @3,
    @"initial_time_to_reconnect_msec" : @1,
    @"session_connection_deadline_msec" : @2,
  };
  NSDictionary<NSString *, id> *reconnectorConfigDictionary =
      PPNReconnectorConfigToNSDictionary(reconnectorConfig);
  XCTAssertEqualObjects(reconnectorConfigDictionary, expectedDictionary);
}

- (void)testPPNNetworkInfoToNSDictionaryWithIPV4 {
  auto network = [self populateNetworkInfoProtoWithAddressFamily:privacy::krypton::NetworkInfo::V4];
  auto expectedDictionary =
      [self expectedNetworkInfoDictionaryWithAddressFamily:privacy::krypton::NetworkInfo::V4];
  auto networkDictionary = PPNNetworkInfoToNSDictionary(network);
  XCTAssertEqualObjects(expectedDictionary, networkDictionary);
}

- (void)testPPNNetworkInfoToNSDictionaryWithIPV6 {
  auto network = [self populateNetworkInfoProtoWithAddressFamily:privacy::krypton::NetworkInfo::V6];
  auto expectedDictionary =
      [self expectedNetworkInfoDictionaryWithAddressFamily:privacy::krypton::NetworkInfo::V6];
  auto networkDictionary = PPNNetworkInfoToNSDictionary(network);
  XCTAssertEqualObjects(expectedDictionary, networkDictionary);
}

- (void)testPPNNetworkInfoToNSDictionaryWithIPV4V6 {
  auto network =
      [self populateNetworkInfoProtoWithAddressFamily:privacy::krypton::NetworkInfo::V4V6];
  auto expectedDictionary =
      [self expectedNetworkInfoDictionaryWithAddressFamily:privacy::krypton::NetworkInfo::V4V6];
  auto networkDictionary = PPNNetworkInfoToNSDictionary(network);
  XCTAssertEqualObjects(expectedDictionary, networkDictionary);
}

#pragma mark Utility

- (::privacy::krypton::NetworkInfo)populateNetworkInfoProtoWithAddressFamily:
    (privacy::krypton::NetworkInfo::AddressFamily)family {
  ::privacy::krypton::NetworkInfo network;
  network.set_network_type(privacy::krypton::NetworkType::UNKNOWN_TYPE);
  network.set_address_family(family);
  network.set_is_metered(true);
  network.set_mtu(1);
  network.set_network_id(2);
  return network;
}

- (NSDictionary<NSString *, id> *)expectedNetworkInfoDictionaryWithAddressFamily:
    (privacy::krypton::NetworkInfo::AddressFamily)family {
  NSString *address;
  switch (family) {
    case privacy::krypton::NetworkInfo::V4:
      address = @"V4";
      break;
    case privacy::krypton::NetworkInfo::V6:
      address = @"V6";
      break;
    case privacy::krypton::NetworkInfo::V4V6:
      address = @"V4V6";
      break;
  }
  return @{
    @"network_type" : @"UNKNOWN",
    @"address_family" : address,
    @"is_metered" : @1,
    @"mtu" : @1,
    @"network_id" : @2,
  };
}

@end
