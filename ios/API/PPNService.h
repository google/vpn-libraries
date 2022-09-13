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
#import "googlemac/iPhone/Shared/PPN/API/PPNServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNTelemetry.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNUDPSessionManaging.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * The PPN service that controls the VPN.
 */
@interface PPNService : NSObject

/**
 * Optional delegate that receives PPN service events, e.g. connection, disconnection.
 */
@property(nonatomic, weak, nullable) id<PPNServiceDelegate> delegate;

/**
 * Whether the PPN service is running.
 */
@property(nonatomic, readonly, getter=isRunning) BOOL running;

/**
 * The debug information about the PPN service.
 */
@property(nonatomic, readonly) NSDictionary<NSString *, id> *debugInfo;

/**
 * Initializes the PPNService with the needed delegates.
 */
- (instancetype)initWithOptions:(NSDictionary<PPNOptionKey, id> *)options
                      OAuthManager:(id<PPNOAuthManaging>)OAuthManager
    virtualNetworkInterfaceManager:
        (id<PPNVirtualNetworkInterfaceManaging>)virtualNetworkInterfaceManager
                 UDPSessionManager:(id<PPNUDPSessionManaging>)UDPSessionManager
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/**
 * Starts the PPN service.
 */
- (void)start;

/**
 * Stops the PPN service.
 */
- (void)stop;

/**
 * Returns a PpnTelemetry object with data about how PPN is currently running.
 */
- (PPNTelemetry *)collectTelemetry;

@end

NS_ASSUME_NONNULL_END
