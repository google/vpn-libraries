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

#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"
#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitorDelegate.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * PPN Monitor of NWPath changes.
 */
@interface PPNNWPathMonitor : NSObject

/**
 * Optional delegate that notifies the changes of NWPath.
 */
@property(nonatomic, weak) id<PPNNWPathMonitorDelegate> delegate;

- (instancetype)initWithOptions:(NSDictionary<PPNOptionKey, id> *)options NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/**
 * Starts monitoring NWPath changes.
 */
- (void)startMonitor;

/**
 * Stops monitoring NWPath changes.
 */
- (void)stopMonitor;

@end

NS_ASSUME_NONNULL_END
