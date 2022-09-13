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

NS_ASSUME_NONNULL_BEGIN

/**
 * The PPN Telemetry.
 */
@interface PPNTelemetry : NSObject

/**
 * The amount of time network extension is running.
 */
@property(nonatomic, readonly) NSTimeInterval ppnServiceUptime;

/**
 * Uptime of PPN connection.
 */
@property(nonatomic, readonly) NSTimeInterval ppnConnectionUptime;

/**
 * Uptime of the network.
 */
@property(nonatomic, readonly) NSTimeInterval networkUptime;

/**
 * Count of disconnection.
 */
@property(nonatomic, readonly) NSInteger disconnectionCount;

// These fields use NSNumber to wrap an NSTimeInterval.

/**
 * Collection of disconnection duration.
 */
@property(nonatomic, readonly) NSArray<NSNumber *> *disconnectionDurations;

@property(nonatomic, readonly) NSArray<NSNumber *> *authLatency;

@property(nonatomic, readonly) NSArray<NSNumber *> *oauthLatency;

@property(nonatomic, readonly) NSArray<NSNumber *> *zincLatency;

@property(nonatomic, readonly) NSArray<NSNumber *> *egressLatency;

@property(nonatomic, readonly) NSInteger successfulRekeys;

@property(nonatomic, readonly) NSInteger networkSwitches;

@end

NS_ASSUME_NONNULL_END
