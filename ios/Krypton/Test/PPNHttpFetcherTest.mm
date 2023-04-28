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
#import <XCTest/XCTest.h>
#include <string>

#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNHttpFetcher.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcher.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcherService.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMockMacros.h"

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
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/json"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
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

- (void)testProtoBodyFetchSuccessfully {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/x-protobuf"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
    NSData *data = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
    fetchCompletionBlock(data, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_proto_body(R"pb(
    use_attestation: true service_type: "123" location_granularity: 2
  )pb");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertFalse(response.has_json_body());
  XCTAssertTrue(response.has_status());
  XCTAssertEqual(response.status().code(), 200);

  XCTAssertTrue(response.has_proto_body());
  NSString *protobody = [[NSString alloc] initWithUTF8String:response.proto_body().c_str()];
  XCTAssertEqualObjects(protobody, @"test data");

  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"no error");
}

- (void)testResponseProtoBodyWithNullBytes {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/x-protobuf"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
    std::string response("test\0 data", 10);
    NSData *data = [NSData dataWithBytes:response.data() length:response.size()];
    fetchCompletionBlock(data, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  privacy::ppn::GetInitialDataRequest init_data_requeset;
  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_proto_body(init_data_requeset.SerializeAsString());

  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  XCTAssertFalse(response.has_json_body());
  XCTAssertTrue(response.has_status());
  XCTAssertEqual(response.status().code(), 200);

  XCTAssertTrue(response.has_proto_body());

  std::string expectedResponse("test\0 data", 10);
  XCTAssertEqual(response.proto_body(), expectedResponse);

  NSString *statusMessage =
      [[NSString alloc] initWithUTF8String:response.status().message().c_str()];
  XCTAssertEqualObjects(statusMessage, @"no error");
}

- (void)testRequestProtoBodyWithNullBytes {
  // tests value with null bytes passed into fetcher.setBodyData
  void (^setBodyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained NSData *bodyData;
    [invocation getArgument:&bodyData atIndex:2];
    unsigned long expectedLength = 10;
    std::string expectedRequestBody("test\0 data", expectedLength);

    std::string storedString((char *)bodyData.bytes, expectedLength);
    XCTAssertEqual(storedString, expectedRequestBody);
  };
  OCMStub([_mockFetcher setBodyData:[OCMArg any]]).andDo(setBodyBlock);

  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/x-protobuf"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
    fetchCompletionBlock(nil, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);

  unsigned long requestBodyLength = 10;
  std::string requestBody("test\0 data", requestBodyLength);
  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_proto_body(requestBody);

  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);
}

- (void)testRequestHeaderWithApiKey {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/json"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
    NSData *data = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
    fetchCompletionBlock(data, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);
  OCMExpect([_mockFetcher setRequestValue:[OCMArg any]
                       forHTTPHeaderField:@"X-Ios-Bundle-Identifier"]);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  (*request.mutable_headers())["X-Goog-Api-Key"] = "some_api_key";
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  OCMVerifyAll(_mockFetcher);
}

- (void)testRequestHeaderWithNoApiKey {
  void (^fetchProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained GTMSessionFetcherCompletionHandler fetchCompletionBlock;
    [invocation getArgument:&fetchCompletionBlock atIndex:2];
    NSDictionary<NSString *, NSString *> *responseHeaders =
        @{@"Content-Type" : @"application/json"};
    OCMStub([_mockFetcher responseHeaders]).andReturn(responseHeaders);
    OCMStub([_mockFetcher statusCode]).andReturn(200);
    NSData *data = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
    fetchCompletionBlock(data, nil);
  };
  OCMStub([_mockFetcher beginFetchWithCompletionHandler:[OCMArg any]]).andDo(fetchProxyBlock);
  OCMReject([_mockFetcher setRequestValue:[OCMArg any]
                       forHTTPHeaderField:@"X-Ios-Bundle-Identifier"]);

  privacy::krypton::HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  privacy::krypton::PPNHttpFetcher httpFetcher;
  privacy::krypton::HttpResponse response = httpFetcher.PostJson(request);

  OCMVerifyAll(_mockFetcher);
}

@end
