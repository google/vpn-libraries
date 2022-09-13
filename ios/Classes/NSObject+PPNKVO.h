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

// A handler which can be registered to receive KVO updates.
typedef void (^PPNKVOHandler)(NSString *keyPath, id object,
                              NSDictionary<NSKeyValueChangeKey, id> *change,
                              void *_Nullable context);

/**
 * KVO is inherently unsafe, because it doesn't retain its observers, and we
 * have no guarantees about which thread the observer may be called on. So, it's
 * possible for KVO to call the observer on one thread while it's being
 * deallocated on another.
 *
 * To make KVO safe, this extension provides an alternate API. An observer can
 * register a block to be called with KVO changes, and then register the
 * keypaths that it cares about separately. KVO will call the block, which can
 * use ARC weak references to safely access other state.
 */
@interface NSObject (PPNKVO)

/**
 * Sets the handler to call with KVO changes registered using the other methods
 * in this extension. This must be called before calling the other methods. The
 * block will be retained for the lifetime of self.
 */
- (void)setObserverHandler:(PPNKVOHandler)handler;

/**
 * Adds a keyPath to be observed, calling the handler when it changes.
 */
- (void)addObserverForKeyPath:(NSString *)keyPath
                      options:(NSKeyValueObservingOptions)options
                      context:(nullable void *)context;

- (void)removeObserverForKeyPath:keyPath;

@end

NS_ASSUME_NONNULL_END
