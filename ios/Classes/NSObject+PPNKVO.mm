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

#import "googlemac/iPhone/Shared/PPN/Classes/NSObject+PPNKVO.h"

#import <objc/runtime.h>

#include "base/logging.h"

/**
 * An object which wraps a handler block and calls it when receiving KVO updates. This object will
 * be created as an associated object and match the lifetime of the observee.
 */
@interface PPNKVOObserver : NSObject {
  PPNKVOHandler _handler;
}

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithHandler:(PPNKVOHandler)handler;

@end

@implementation PPNKVOObserver

- (instancetype)initWithHandler:(PPNKVOHandler)handler {
  self = [super init];
  if (self) {
    _handler = handler;
  }
  return self;
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSKeyValueChangeKey, id> *)change
                       context:(void *)context {
  _handler(keyPath, object, change, context);
}

@end

@implementation NSObject (PPNKVO)

- (void)setObserverHandler:(PPNKVOHandler)handler {
  PPNKVOObserver *observer = [[PPNKVOObserver alloc] initWithHandler:handler];
  objc_setAssociatedObject(self, @selector(setObserverHandler:), observer, OBJC_ASSOCIATION_RETAIN);
}

- (void)addObserverForKeyPath:(NSString *)keyPath
                      options:(NSKeyValueObservingOptions)options
                      context:(void *)context {
  PPNKVOObserver *observer = objc_getAssociatedObject(self, @selector(setObserverHandler:));
  if (!observer) {
    LOG(FATAL) << "setObserverHandler: must be called before "
                  "addObserverForKeyPath:options:context:handler:";
    return;
  }
  [self addObserver:observer forKeyPath:keyPath options:options context:context];
}

- (void)removeObserverForKeyPath:keyPath {
  PPNKVOObserver *observer = objc_getAssociatedObject(self, @selector(setObserverHandler:));
  if (!observer) {
    LOG(FATAL) << "setObserverHandler: must be called before removeObserverForKeyPath:";
    return;
  }
  [self removeObserver:observer forKeyPath:keyPath];
}

@end
