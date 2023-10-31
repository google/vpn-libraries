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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetry+Internal.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNTelemetry.h"

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"

@implementation PPNTelemetry

- (instancetype)initWithKryptonTelemetry:
                    (const privacy::krypton::KryptonTelemetry &)kryptonTelemetry
                           serviceUptime:(NSTimeInterval)serviceUptime
                        connectionUptime:(NSTimeInterval)connectionUptime
                           networkUptime:(NSTimeInterval)networkUptime
                  disconnectionDurations:(NSArray<NSNumber *> *)disconnectionDurations
                      disconnectionCount:(NSInteger)disconnectionCount {
  self = [super init];
  if (self != nullptr) {
    NSMutableArray<NSNumber *> *mutableAuthLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.auth_latency()) {
      [mutableAuthLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _authLatency = mutableAuthLatency;
    NSMutableArray<NSNumber *> *mutableOAuthLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.oauth_latency()) {
      [mutableOAuthLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _oauthLatency = mutableOAuthLatency;
    NSMutableArray<NSNumber *> *mutableZincLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.zinc_latency()) {
      [mutableZincLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _zincLatency = mutableZincLatency;
    NSMutableArray<NSNumber *> *mutableEgressLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.egress_latency()) {
      [mutableEgressLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _egressLatency = mutableEgressLatency;
    NSMutableArray<NSNumber *> *mutableNetworkSwitchLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.network_switch_latency()) {
      [mutableNetworkSwitchLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _networkSwitchLatency = mutableNetworkSwitchLatency;
    NSMutableArray<NSNumber *> *mutableControlPlaneSuccessLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.control_plane_success_latency()) {
      [mutableControlPlaneSuccessLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _controlPlaneSuccessLatency = mutableControlPlaneSuccessLatency;
    NSMutableArray<NSNumber *> *mutableControlPlaneFailureLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.control_plane_failure_latency()) {
      [mutableControlPlaneFailureLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _controlPlaneFailureLatency = mutableControlPlaneFailureLatency;
    NSMutableArray<NSNumber *> *mutableDataPlaneConnectingLatency = [[NSMutableArray alloc] init];
    for (const auto &latency : kryptonTelemetry.data_plane_connecting_latency()) {
      [mutableDataPlaneConnectingLatency addObject:[self convertDurationToNSNumber:latency]];
    }
    _dataPlaneConnectingLatency = mutableDataPlaneConnectingLatency;
    _networkSwitches = kryptonTelemetry.network_switches();
    _successfulRekeys = kryptonTelemetry.successful_rekeys();
    _ppnServiceUptime = serviceUptime;
    _ppnConnectionUptime = connectionUptime;
    _networkUptime = networkUptime;
    _disconnectionDurations = disconnectionDurations;
    _disconnectionCount = disconnectionCount;
    _successfulNetworkSwitches = kryptonTelemetry.successful_network_switches();
    _controlPlaneAttempts = kryptonTelemetry.control_plane_attempts();
    _controlPlaneSuccesses = kryptonTelemetry.control_plane_successes();
    _dataPlaneConnectingAttempts = kryptonTelemetry.data_plane_connecting_attempts();
    _dataPlaneConnectingSuccesses = kryptonTelemetry.data_plane_connecting_successes();
    _healthCheckAttempts = kryptonTelemetry.health_check_attempts();
    _healthCheckSuccesses = kryptonTelemetry.health_check_successes();
    _tokenUnblindFailureCount = kryptonTelemetry.token_unblind_failure_count();
  }
  return self;
}

- (NSString *)description {
  return [[NSString alloc]
      initWithFormat:
          @"<%@: %p; authLatency:%@ oauthLatency:%@ zincLatency:%@ egressLatency:%@ "
          @"networkSwitches:%d successfulRekeys:%d serviceUptime:%lf connectionUptime:%lf "
          @"networkUptime:%lf disconnectionDurations:%@ disconnectionCount:%ld>",
          NSStringFromClass([self class]), self, [_authLatency componentsJoinedByString:@","],
          [_oauthLatency componentsJoinedByString:@","],
          [_zincLatency componentsJoinedByString:@","],
          [_egressLatency componentsJoinedByString:@","], (int)_networkSwitches,
          (int)_successfulRekeys, _ppnServiceUptime, _ppnConnectionUptime, _networkUptime,
          [_disconnectionDurations componentsJoinedByString:@","], (long)_disconnectionCount];
}

#pragma mark - private method

- (NSNumber *)convertDurationToNSNumber:(google::protobuf::Duration)duration {
  return [NSNumber numberWithDouble:absl::ToDoubleSeconds(absl::Seconds(duration.seconds()) +
                                                          absl::Nanoseconds(duration.nanos()))];
}

@end
