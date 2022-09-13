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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNUptimeTracker.h"

@implementation PPNUptimeTracker {
  /**
   * The time that this metric was last "started", or null if it is not
   * currently up.
   */
  NSDate *_startTime;

  /**
   * The total duration of how long this metric has been "up" since it was last
   * collected, not including the current run.
   */
  NSTimeInterval _totalTime;

  PPNClock *_clock;
}

- (instancetype)initWithClock:(PPNClock *)clock {
  self = [super init];
  if (self) {
    _clock = clock;
  }
  return self;
}

- (void)start {
  @synchronized(self) {
    if (_startTime) {
      // The span was started multiple times, but that's fine. For example, a network may become
      // available when there was already a network available. Just consider it a no-op.
      return;
    }
    _startTime = [_clock now];
  }
}

- (void)stop {
  @synchronized(self) {
    if (!_startTime) {
      // The span was stopped multiple times, but that's fine. For example, we may get multiple
      // notifications that no network is available. Just consider it a no-op.
      return;
    }
    // Measure the elapsed duration and add it to the running total.
    NSDate *now = [_clock now];
    NSTimeInterval elapsedTime = [now timeIntervalSinceDate:_startTime];
    _totalTime += elapsedTime;
    // Reset the state to not be started.
    _startTime = nil;
  }
}

- (NSTimeInterval)collectDuration {
  @synchronized(self) {
    // Grab the accumulated uptime and reset the counter.
    NSTimeInterval duration = _totalTime;
    _totalTime = 0.0;

    // If it's still running, grab the current elapsed time and reset the start time to now.
    if (_startTime) {
      NSDate *now = [_clock now];
      NSTimeInterval elapsedTime = [now timeIntervalSinceDate:_startTime];
      duration = duration + elapsedTime;

      _startTime = now;
    }
    return duration;
  }
}

@end
