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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeDurationTracker.h"

@implementation PPNUptimeDurationTracker {
  NSMutableArray<NSNumber *> *_uptimeDurations;
  PPNUptimeTracker *_uptimeTracker;
}

- (instancetype)initWithClock:(PPNClock *)clock {
  self = [super init];
  if (self) {
    _uptimeDurations = [[NSMutableArray alloc] init];
    PPNUptimeTracker *tracker = [[PPNUptimeTracker alloc] initWithClock:clock];
    _uptimeTracker = tracker;
  }
  return self;
}

- (void)start {
  @synchronized(self) {
    [_uptimeTracker start];
  }
}

- (void)stop {
  @synchronized(self) {
    [_uptimeTracker stop];
    [self captureDuration];
  }
}

- (NSArray<NSNumber *> *)collectDurations {
  @synchronized(self) {
    [self captureDuration];
    NSArray<NSNumber *> *durations = [_uptimeDurations copy];
    _uptimeDurations = [NSMutableArray array];
    return durations;
  }
}

#pragma mark - private methods

- (void)captureDuration {
  NSTimeInterval duration = [_uptimeTracker collectDuration];
  if (duration > 0) {
    [_uptimeDurations addObject:[NSNumber numberWithDouble:duration]];
  }
}

@end
