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
#import "googlemac/iPhone/Shared/PPN/API/PPNNetworkType.h"
#import "privacy/net/krypton/proto/network_info.proto.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * The PPN network info.
 */
@interface PPNNetworkInfo : NSObject

/**
 * PPN address family.
 */
typedef NS_ENUM(NSUInteger, PPNAddressFamily) {
  V4 = 1,
  V6 = 2,
  V4V6 = 3,
};

/**
 * Initializes the class with a NetworkInfo.
 */
- (instancetype)initWithNetworkInfo:(const privacy::krypton::NetworkInfo&)networkInfo
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/**
 * Type of the network.
 */
@property(nonatomic, readonly) PPNNetworkType networkType;

/**
 * Whether the network is a metered network.
 */
@property(nonatomic, readonly, getter=isMetered) BOOL metered;

/**
 * Address family of the network.
 */
@property(nonatomic, readonly) PPNAddressFamily addressFamily;

/**
 * Maximum Transmission Unit (MTU) of the network.
 */
@property(nonatomic, readonly) unsigned int MTU;

/**
 * Id of the network.
 */
@property(nonatomic, readonly) int64_t networkID;

@end

NS_ASSUME_NONNULL_END
