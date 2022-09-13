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

NS_ASSUME_NONNULL_BEGIN

/**
 * The PPN connection status.
 */
@interface PPNConnectionStatus : NSObject

/**
 * PPN connection security type.
 */
typedef NS_ENUM(NSUInteger, PPNSecurityType) {
  UNKNOWN_SECURITY = 0,
  SECURE = 1,
  INSECURE = 2,
};

/**
 * PPN connection quality.
 */
typedef NS_ENUM(NSUInteger, PPNConnectionQuality) {
  UNKNOWN_QUALITY = 0,
  EXCELLENT = 1,
  GOOD = 2,
  FAIR = 3,
  POOR = 4,
  NO_SIGNAL = 5,
};

/**
 * Type of the network connection.
 */
@property(nonatomic, readonly) PPNNetworkType networkType;

/**
 * Security type of the connection.
 */
@property(nonatomic, readonly) PPNSecurityType security;

/**
 * Connection quality.
 */
@property(nonatomic, readonly) PPNConnectionQuality quality;

@end

NS_ASSUME_NONNULL_END
