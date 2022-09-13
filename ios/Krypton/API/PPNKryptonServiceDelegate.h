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
#import "googlemac/iPhone/Shared/PPN/Classes/PPNNetworkInfo.h"

#include "privacy/net/krypton/proto/network_info.proto.h"

@class PPNKryptonService;

NS_ASSUME_NONNULL_BEGIN

@protocol PPNKryptonServiceDelegate <NSObject>

@optional

/**
 * Called when the Krypton service is connected.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService didConnect:(PPNConnectionStatus *)status;

/**
 * Called when the Krypton starts trying to establish a new session.
 */
- (void)kryptonServiceConnecting:(PPNKryptonService *)kryptonService;

/**
 * Called when the PPN control plane connects to the backend.
 */
- (void)kryptonServiceDidConnectControlPlane:(PPNKryptonService *)kryptonService;

/**
 * Called to notify the Krypton clients about the metadata of the data connection.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService
       didUpdateStatus:(PPNConnectionStatus *)status;

/**
 * Called when the PPN data plane disconnects from the backend.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService
         didDisconnect:(PPNDisconnectionStatus *)disconnectionstatus;

/**
 * Called when Krypton decides the current network has failed.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService
      didFailWithError:(NSError *)error
           networkInfo:(PPNNetworkInfo *)networkInfo;

/**
 * Called whenever Krypton cannot continue. Must call the -stop method when this event is received.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService
    didPermanentlyFailWithError:(NSError *)error;

/**
 * Called whenever Krypton crashes. Must call the -stop method when this event is received.
 */
- (void)kryptonServiceDidCrash:(PPNKryptonService *)kryptonService;

/**
 * Called when Krypton starts a reconnection sequence.
 */
- (void)kryptonService:(PPNKryptonService *)kryptonService
    waitingToReconnect:(PPNReconnectStatus *)reconnectStatus;

@end

NS_ASSUME_NONNULL_END
