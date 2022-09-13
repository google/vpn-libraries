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

#import "googlemac/iPhone/Shared/PPN/API/PPNLogging.h"

NS_ASSUME_NONNULL_BEGIN

/** ObjC wrapper for the C++ PPNLogSink so it can be used in the Swift code. */
NS_SWIFT_NAME(LogSinkWrapper)
NS_REFINED_FOR_SWIFT
@interface PPNLogSinkWrapper : NSObject

/** A custom logger that handles all C++ log entries. */
- (void)setCustomLogger:(id<PPNLogging>)logger;

@end

NS_ASSUME_NONNULL_END
