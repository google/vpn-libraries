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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNClock.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetry+Internal.h"

#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * Singleton responsible for tracking telemetry data about how well PPN is running.
 */
@interface PPNTelemetryManager : NSObject

/**
 * Initiates PPNTelemetryManager with a PPN clock.
 */
- (instancetype)initWithClock:(PPNClock *)clock NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/**
 * Should be called when the network extension is started.
 */
- (void)notifyStarted;

/**
 * Should be called when the PPN service stops.
 */
- (void)notifyStopped;

/**
 * Should be called when PPN connects.
 */
- (void)notifyConnected;

/**
 * Should be called when PPN disconnects.
 */
- (void)notifyDisconnected;

/**
 * Should be called when any network is available, according to Xenon.
 */
- (void)notifyNetworkAvailable;

/**
 * Should be called when no network is available, according to Xenon.
 */
- (void)notifyNetworkUnavailable;

/**
 * Returns a collection of the metrics since the last time collect was called, and resets them.
 * @param kryptonTelemetry telemetry data from Krypton.
 */
- (PPNTelemetry *)collect:(privacy::krypton::KryptonTelemetry)kryptonTelemetry;

@end

NS_ASSUME_NONNULL_END
