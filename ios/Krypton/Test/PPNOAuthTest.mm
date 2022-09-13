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

#import "googlemac/iPhone/Shared/PPN/API/PPNOAuthManaging.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNOAuth.h"
#import "third_party/absl/status/status.h"
#import "third_party/absl/status/statusor.h"
#import "third_party/objective_c/ocmock/v3/Source/OCMock/OCMock.h"

@interface PPNOAuthTest : XCTestCase
@end

@implementation PPNOAuthTest {
  id _mockOAuthManager;
}

- (void)setUp {
  [super setUp];
  _mockOAuthManager = OCMProtocolMock(@protocol(PPNOAuthManaging));
}

- (void)testGetOAuthTokenSuccessfully {
  privacy::krypton::PPNOAuth oauth = privacy::krypton::PPNOAuth(_mockOAuthManager);

  void (^creationProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained PPNOAuthTokenCompletionHandler completionBlock;
    [invocation getArgument:&completionBlock atIndex:2];
    completionBlock(@"test token", nil);
  };
  OCMStub([_mockOAuthManager oauthTokenWithCompletion:[OCMArg any]]).andDo(creationProxyBlock);

  absl::StatusOr<std::string> tokenStatus = oauth.GetOAuthToken();
  XCTAssertEqual(tokenStatus.value(), "test token");
}

- (void)testGetOAuthTokenFailed {
  privacy::krypton::PPNOAuth oauth = privacy::krypton::PPNOAuth(_mockOAuthManager);

  void (^creationProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained PPNOAuthTokenCompletionHandler completionBlock;
    [invocation getArgument:&completionBlock atIndex:2];
    NSError *error = [[NSError alloc] initWithDomain:@"test.domain" code:1 userInfo:nil];
    // Set a test token on purpose to verify the GetOAuthToken method should fail when both the
    // token and the error are non-nil.
    completionBlock(@"test token", error);
  };
  OCMStub([_mockOAuthManager oauthTokenWithCompletion:[OCMArg any]]).andDo(creationProxyBlock);

  absl::StatusOr<std::string> tokenStatus = oauth.GetOAuthToken();
  absl::Status errorStatus = tokenStatus.status();
  XCTAssertEqual(errorStatus.code(), absl::StatusCode::kInternal);
  std::string errorMessage = std::string(errorStatus.message());
  NSString *errorMessageString = [[NSString alloc] initWithUTF8String:errorMessage.c_str()];
  XCTAssertEqualObjects(errorMessageString, @"Failed to get the OAuth token: The operation "
                                            @"couldn’t be completed. (test.domain error 1.)");
}

- (void)testGetOAuthTokenFailedWithUnknownError {
  privacy::krypton::PPNOAuth oauth = privacy::krypton::PPNOAuth(_mockOAuthManager);

  void (^creationProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    __unsafe_unretained PPNOAuthTokenCompletionHandler completionBlock;
    [invocation getArgument:&completionBlock atIndex:2];
    completionBlock(nil, nil);
  };
  OCMStub([_mockOAuthManager oauthTokenWithCompletion:[OCMArg any]]).andDo(creationProxyBlock);

  absl::StatusOr<std::string> tokenStatus = oauth.GetOAuthToken();
  absl::Status errorStatus = tokenStatus.status();
  XCTAssertEqual(errorStatus.code(), absl::StatusCode::kUnknown);
  std::string errorMessage = std::string(errorStatus.message());
  NSString *errorMessageString = [[NSString alloc] initWithUTF8String:errorMessage.c_str()];
  XCTAssertEqualObjects(errorMessageString, @"Failed to get the OAuth token: Unknown error.");
}

- (void)testGetOAuthTokenFailedWithInvalidOAuthManager {
  privacy::krypton::PPNOAuth oauth = privacy::krypton::PPNOAuth(nil);

  absl::StatusOr<std::string> tokenStatus = oauth.GetOAuthToken();
  absl::Status errorStatus = tokenStatus.status();
  XCTAssertEqual(errorStatus.code(), absl::StatusCode::kFailedPrecondition);
  std::string errorMessage = std::string(errorStatus.message());
  NSString *errorMessageString = [[NSString alloc] initWithUTF8String:errorMessage.c_str()];
  XCTAssertEqualObjects(errorMessageString, @"Failed to get the OAuth token: The OAuth manager "
                                            @"must conform to the PPNOAuthManaging protocol.");
}

- (void)testGetOAuthTokenTimedOut {
  privacy::krypton::PPNOAuth oauth = privacy::krypton::PPNOAuth(_mockOAuthManager);

  __block __unsafe_unretained PPNOAuthTokenCompletionHandler completionBlock;
  void (^creationProxyBlock)(NSInvocation *) = ^(NSInvocation *invocation) {
    [invocation getArgument:&completionBlock atIndex:2];
  };
  OCMStub([_mockOAuthManager oauthTokenWithCompletion:[OCMArg any]]).andDo(creationProxyBlock);

  oauth.SetTokenCreationTimeout(0.5);
  absl::StatusOr<std::string> tokenStatus = oauth.GetOAuthToken();
  absl::Status errorStatus = tokenStatus.status();
  XCTAssertEqual(errorStatus.code(), absl::StatusCode::kInternal);
  std::string errorMessage = std::string(errorStatus.message());
  NSString *errorMessageString = [[NSString alloc] initWithUTF8String:errorMessage.c_str()];
  XCTAssertEqualObjects(errorMessageString, @"Failed to get the OAuth token: Timeout.");
}

@end
