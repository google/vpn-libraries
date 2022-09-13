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

#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNHttpFetcher.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcher.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcherService.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

@interface PPNHttpFetcherTest : XCTestCase
@end

@implementation PPNHttpFetcherTest {
  id _mockFetcher;
  id _mockFetcherService;
  privacy::krypton::PPNHttpFetcher _httpFetcher;
}

- (void)setUp {
  [super setUp];
  _mockFetcher = OCMClassMock([GTMSessionFetcher class]);
  _mockFetcherService = OCMClassMock([GTMSessionFetcherService class]);
  OCMStub([_mockFetcherService alloc]).andReturn(_mockFetcherService);
  OCMStub([_mockFetcherService fetcherWithURLString:[OCMArg any]]).andReturn(_mockFetcher);
}

- (void)testFetchSuccessfully {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSData *data = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
    fetchCompletionBlock(data, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertTrue(response.has_json_body());
  XCTAssertTrue(response.has_status());
  NSString *jsonBody = [[NSString alloc] initWithUTF8String:response.json_body().c_str()];
  XCTAssertEqualObjects(jsonBody, @"test data");
  XCTAssertEqual(response.status().code(), 200);
  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"no error");
}

- (void)testFetchWithServerError {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSError *fetcherError = [[NSError alloc] initWithDomain:kGTMSessionFetcherStatusDomain
                                                       code:GTMSessionFetcherStatusBadRequest
                                                   userInfo:nil];
    // Set data on purpose to verify the response doesn't contain the Json body when there's an
    // error.
    NSData *data = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
    fetchCompletionBlock(data, fetcherError);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertFalse(response.has_json_body());
  XCTAssertTrue(response.has_status());
  XCTAssertEqual(response.status().code(), 400);
  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"bad request");
}

- (void)testFetchWithNonServerError {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSError *fetcherError = [[NSError alloc] initWithDomain:kGTMSessionFetcherErrorDomain
                                                       code:GTMSessionFetcherErrorDownloadFailed
                                                   userInfo:nil];
    fetchCompletionBlock(nil, fetcherError);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertFalse(response.has_json_body());
  XCTAssertTrue(response.has_status());
  XCTAssertEqual(response.status().code(), 500);
  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"internal server error");
}

- (void)testFetchWithTimeout {
  __block __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  httpFetcher.SetRequestTimeout(0.5);
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertFalse(response.has_json_body());
  XCTAssertTrue(response.has_status());
  XCTAssertEqual(response.status().code(), 408);
  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"request timed out");
}

@end
