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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetryManager.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeDurationTracker.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeTracker.h"

#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"

@implementation PPNTelemetryManager {
  PPNUptimeTracker *_serviceTracker;
  PPNUptimeTracker *_connectionTracker;
  PPNUptimeTracker *_networkTracker;
  PPNUptimeDurationTracker *_disconnectionDurationTracker;
  NSInteger _disconnectionCount;
  BOOL _running;
  BOOL _connected;
  BOOL _disconnected;
}

- (instancetype)initWithClock:(PPNClock *)clock {
  self = [super init];
  if (self != nullptr) {
    _serviceTracker = [[PPNUptimeTracker alloc] initWithClock:clock];
    _connectionTracker = [[PPNUptimeTracker alloc] initWithClock:clock];
    _networkTracker = [[PPNUptimeTracker alloc] initWithClock:clock];
    _disconnectionDurationTracker = [[PPNUptimeDurationTracker alloc] initWithClock:clock];
  }
  return self;
}

- (void)notifyStarted {
  @synchronized(self) {
    _running = YES;
    [_serviceTracker start];
  }
}

- (void)notifyStopped {
  @synchronized(self) {
    if (_connected) {
      _connected = NO;
      PPNLog(@"[%@] PPN was marked as stopped, even though it's still connected. Marking "
             @"disconnected.",
             self.debugDescription);
    }
    _running = NO;
    [_disconnectionDurationTracker stop];
    [_serviceTracker stop];
  }
}

- (void)notifyConnected {
  @synchronized(self) {
    if (!_running) {
      PPNLog(@"[%@] PPN was marked as connected even though the service is not running.",
             self.debugDescription);
    }
    _connected = YES;
    [_connectionTracker start];
    [_disconnectionDurationTracker stop];
    _disconnected = NO;
  }
}

- (void)notifyDisconnected {
  @synchronized(self) {
    if (!_disconnected) {
      _disconnected = YES;
      _disconnectionCount++;
    }
    _connected = NO;
    [_connectionTracker stop];
    [_disconnectionDurationTracker start];
  }
}

- (void)notifyNetworkAvailable {
  @synchronized(self) {
    if (!_running) {
      PPNLog(@"[%@] PPN was marked as network available, but not marked as running.",
             self.debugDescription);
    }
    if (_disconnected) {
      [_disconnectionDurationTracker start];
    }
    [_networkTracker start];
  }
}

- (void)notifyNetworkUnavailable {
  @synchronized(self) {
    if (!_running) {
      PPNLog(@"[%@] PPN was marked as network unavailable, but not marked as running.",
             self.debugDescription);
    }
    [_disconnectionDurationTracker stop];
    [_networkTracker stop];
  }
}

- (PPNTelemetry *)collect:(privacy::krypton::KryptonTelemetry)kryptonTelemetry {
  @synchronized(self) {
    PPNTelemetry *ppnTelemetry = [[PPNTelemetry alloc]
        initWithKryptonTelemetry:kryptonTelemetry
                   serviceUptime:[_serviceTracker collectDuration]
                connectionUptime:[_connectionTracker collectDuration]
                   networkUptime:[_networkTracker collectDuration]
          disconnectionDurations:[_disconnectionDurationTracker collectDurations]
              disconnectionCount:_disconnectionCount];
    _disconnectionCount = 0;
    return ppnTelemetry;
  }
}

@end
