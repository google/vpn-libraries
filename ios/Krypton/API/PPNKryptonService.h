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

#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonServiceDelegate.h"

#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"

@protocol PPNUDPSessionManaging;

NS_ASSUME_NONNULL_BEGIN

/**
 * The wrapper of the Krypton C++ library.
 */
@interface PPNKryptonService : NSObject

/**
 * Optional delegate that receives Krypton service events, e.g. connection, disconnection.
 */
@property(nonatomic, weak) id<PPNKryptonServiceDelegate> delegate;

/**
 * The debug information about the Krypton service.
 */
@property(nonatomic, readonly) privacy::krypton::KryptonDebugInfo debugInfo;

/**
 * Whether safe disconnected is enabled.
 */
@property(nonatomic, assign, getter=isSafeDisconnectEnabled) BOOL safeDisconnectEnabled;

/**
 * Initializes the class with a @c PPNOAuthManaging @c PPNUDPSessionManaging and
 * @c PPNVirtualNetworkInterfaceManaging.
 */
- (instancetype)initWithOAuthManager:(id<PPNOAuthManaging>)OAuthManager
      virtualNetworkInterfaceManager:
          (id<PPNVirtualNetworkInterfaceManaging>)virtualNetworkInterfaceManager
                ppnUDPSessionManager:(id<PPNUDPSessionManaging>)ppnUDPSessionManager
                          timerQueue:(dispatch_queue_t)timerQueue;

/**
 * Starts the Krypton service.
 */
- (void)startWithConfiguration:(const privacy::krypton::KryptonConfig &)configuration;

/**
 * Stops the Krypton service, closing any open connections.
 */
- (void)stop;

/**
 * Sets network.
 */
- (absl::Status)setNetwork:(const privacy::krypton::NetworkInfo &)networkInfo;

/**
 * No network is available.
 */
- (absl::Status)setNoNetworkAvailable;

/**
 * Returns a PpnTelemetry object with data about how PPN is currently running.
 */
- (privacy::krypton::KryptonTelemetry)collectTelemetry;

/**
 * Returns @c Krypton's debug info proto.
 */
- (privacy::krypton::KryptonDebugInfo)debugInfo;

@end

NS_ASSUME_NONNULL_END
