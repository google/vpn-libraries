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

/**
 * PPN OAuth token creation completion handler.
 */
typedef void (^PPNOAuthTokenCompletionHandler)(NSString *_Nullable token, NSError *_Nullable error);

/**
 * PPN user Email creation completion handler.
 */
typedef void (^PPNUserEmailCompletionHandler)(NSString *_Nullable email, NSError *_Nullable error);

/**
 * The OAuth manager that provides the OAuth access token.
 */
@protocol PPNOAuthManaging <NSObject>

/**
 * Gets an OAuth token for the user. Returns the OAuth token in the completion block or
 * returns an error when it fails to get the OAuth token.
 */
- (void)oauthTokenWithCompletion:(PPNOAuthTokenCompletionHandler)completion;

/**
 * Gets the user Email with completion handler.
 */
- (void)userEmailWithCompletion:(PPNUserEmailCompletionHandler)completion;

@end

NS_ASSUME_NONNULL_END
