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

#import <XCTest/XCTest.h>

// A helper wrapper around a BOOL and an NSCondition.
@interface PPNConditionBool : NSObject {
  BOOL _value;
  NSCondition *_condition;
}

// Blocks until the value becomes true.
- (void)waitForTrue;

// Sets the value to true.
- (void)setTrue;

@end

@implementation PPNConditionBool

- (instancetype)init {
  self = [super init];
  if (self) {
    _value = NO;
    _condition = [[NSCondition alloc] init];
  }
  return self;
}

- (void)waitForTrue {
  [_condition lock];
  while (!_value) {
    [_condition wait];
  }
  [_condition unlock];
}

- (void)setTrue {
  [_condition lock];
  _value = YES;
  [_condition signal];
  [_condition unlock];
}

@end

/**
 * An object that uses KVO to observe another object, instrumented for testing lifecycle changes.
 */
@interface PPNKVOTestObserver : NSObject {
  // The object being observed.
  id _observee;

  // A condition that becomes true at the beginning of this class's deallocation.
  PPNConditionBool *_deallocStarted;

  // A condition that will be waited on in deallocation, so that the test can perform checks while
  // the object is still being deallocated.
  PPNConditionBool *_checksComplete;
}

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithObservee:(id)observee
                  deallocStarted:(PPNConditionBool *)deallocStarted
                  checksComplete:(PPNConditionBool *)checksComplete;

- (void)setHandler:(PPNKVOHandler)handler;

@end

@implementation PPNKVOTestObserver

- (instancetype)initWithObservee:(id)observee
                  deallocStarted:(PPNConditionBool *)deallocStarted
                  checksComplete:(PPNConditionBool *)checksComplete {
  self = [super init];
  if (self) {
    _observee = observee;
    _deallocStarted = deallocStarted;
    _checksComplete = checksComplete;
  }
  return self;
}

- (void)setHandler:(PPNKVOHandler)handler {
  [_observee setObserverHandler:handler];
  [_observee addObserverForKeyPath:@"prop" options:0 context:NULL];
}
- (void)dealloc {
  NSLog(@"observer dealloc started");
  [_deallocStarted setTrue];
  NSLog(@"observer waiting for test checks");
  [_checksComplete waitForTrue];
  NSLog(@"removing observer");
  [_observee removeObserverForKeyPath:@"prop"];
  NSLog(@"dealloc complete");
}

@end

/**
 * A simple object with a property that can be observed using KVO.
 */
@interface PPNKVOTestObservee : NSObject
@property(nonatomic, assign) int prop;
@end

@implementation PPNKVOTestObservee
@end

@interface PPNKVOTest : XCTestCase
@end

@implementation PPNKVOTest

/**
 * Tests the normal case, where the observer is still valid.
 */
- (void)testNonnullObserver {
  PPNConditionBool *deallocStarted = [[PPNConditionBool alloc] init];
  PPNConditionBool *checksComplete = [[PPNConditionBool alloc] init];

  PPNKVOTestObservee *observee = [[PPNKVOTestObservee alloc] init];

  PPNKVOTestObserver *observer = [[PPNKVOTestObserver alloc] initWithObservee:observee
                                                               deallocStarted:deallocStarted
                                                               checksComplete:checksComplete];

  __weak PPNKVOTestObserver *weakObserver = observer;
  __block BOOL handlerCalled = NO;

  [observer setHandler:^(NSString *keyPath, id object,
                         NSDictionary<NSKeyValueChangeKey, id> *change, void *context) {
    NSLog(@"Called observer block for %@", keyPath);
    PPNKVOTestObserver *strongObserver = weakObserver;
    XCTAssertNotNil(strongObserver);
    handlerCalled = YES;
  }];

  observee.prop = 2;

  XCTAssertTrue(handlerCalled);

  // The observer doesn't need to block on anything else.
  [checksComplete setTrue];
}

/**
 * Tests the case where the observer is being deallocated when KVO send an update.
 */
- (void)testNullObserver {
  PPNConditionBool *deallocStarted = [[PPNConditionBool alloc] init];
  PPNConditionBool *checksComplete = [[PPNConditionBool alloc] init];

  dispatch_queue_t q = dispatch_queue_create("com.google.ppn.kvo-test", DISPATCH_QUEUE_SERIAL);

  PPNKVOTestObservee *observee = [[PPNKVOTestObservee alloc] init];

  __block BOOL handlerCalled = NO;

  @autoreleasepool {
    PPNKVOTestObserver *observer = [[PPNKVOTestObserver alloc] initWithObservee:observee
                                                                 deallocStarted:deallocStarted
                                                                 checksComplete:checksComplete];

    __weak PPNKVOTestObserver *weakObserver = observer;

    [observer setHandler:^(NSString *keyPath, id object,
                           NSDictionary<NSKeyValueChangeKey, id> *change, void *context) {
      NSLog(@"Called observer block for %@", keyPath);
      PPNKVOTestObserver *strongObserver = weakObserver;
      XCTAssertNil(strongObserver);
      handlerCalled = YES;
    }];

    // Start an async task to call the observer after it's started deallocating.
    dispatch_async(q, ^{
      // Wait for the observer to start deallocating.
      NSLog(@"waiting for dealloc");
      [deallocStarted waitForTrue];

      // Make the observee emit a KVO event.
      NSLog(@"changing property");
      observee.prop = 2;
      XCTAssertTrue(handlerCalled);

      // Signal the observer that it can finish deallocation.
      [checksComplete setTrue];
      NSLog(@"block done");
    });

    // At the end of this autorelease block, the observer will be deallocated, because there are no
    // more strong references to it. The block will block until the object finishes deallocating,
    // which will be after the checks above complete.
  }
}

@end
