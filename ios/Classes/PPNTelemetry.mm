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
    _networkSwitches = kryptonTelemetry.network_switches();
    _successfulRekeys = kryptonTelemetry.successful_rekeys();
    _ppnServiceUptime = serviceUptime;
    _ppnConnectionUptime = connectionUptime;
    _networkUptime = networkUptime;
    _disconnectionDurations = disconnectionDurations;
    _disconnectionCount = disconnectionCount;
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
