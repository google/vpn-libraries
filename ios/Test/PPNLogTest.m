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

#import <XCTest/XCTest.h>

#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNLogSinkWrapper.h"

#include "googlemac/iPhone/Shared/PPN/API/PPNLogging.h"

/** Fake implementation of @c PPNLogging. */
@interface PPNFakeLogger : NSObject <PPNLogging>

/** Block to be called with the same @ message that passed into @c log:. */
@property(atomic, copy, nullable) void (^logCallback)(NSString *);

@end

@implementation PPNFakeLogger

- (nullable NSError *)log:(NSString *)message {
  self.logCallback(message);
  return nil;
}

@end

@interface PPNLogTest : XCTestCase
@end

@implementation PPNLogTest {
  PPNLogSinkWrapper *_logSink;
  PPNFakeLogger *_fakeLogger;
}

- (void)setUp {
  [super setUp];
  _fakeLogger = [[PPNFakeLogger alloc] init];
  _logSink = [[PPNLogSinkWrapper alloc] init];
  [_logSink setCustomLogger:_fakeLogger];
}

- (void)testPPNLog {
  XCTestExpectation *expectation = [self expectationWithDescription:@"expected message is logged"];

  NSString *message = @"hello world";

  _fakeLogger.logCallback = ^(NSString *log) {
    [log containsString:message];
    [expectation fulfill];
  };

  PPNLog(@"%@", message);

  [self waitForExpectations:@[ expectation ] timeout:1];
}

@end
