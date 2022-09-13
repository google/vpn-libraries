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

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNReconnectStatus.h"

@class PPNService;

NS_ASSUME_NONNULL_BEGIN

/**
 * Delegate methods for receiving PPN service events.
 */
@protocol PPNServiceDelegate <NSObject>

@optional

/**
 * Called when the PPN service is started.
 */
- (void)PPNServiceDidStart:(PPNService *)PPNService;

/**
 * Called when the PPN service is connecting.
 */
- (void)PPNServiceConnecting:(PPNService *)PPNService;

/**
 * Called when the PPN service stops.
 */
- (void)PPNService:(PPNService *)PPNService didStopWithError:(nullable NSError *)error;

/**
 * Called when the PPN connects.
 */
- (void)PPNService:(PPNService *)PPNService didConnectWithStatus:(PPNConnectionStatus *)status;

/**
 * Called periodically when the PPN connection status is updated.
 */
- (void)PPNService:(PPNService *)PPNService didUpdateStatus:(PPNConnectionStatus *)status;

/**
 * Called when the PPN service disconnects.
 */
- (void)PPNService:(PPNService *)PPNService
     didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus;

/**
 * Called when the PPN service is waiting to reconnect.
 */
- (void)PPNService:(PPNService *)PPNService waitingToReconnect:(PPNReconnectStatus *)status;

@end

NS_ASSUME_NONNULL_END
