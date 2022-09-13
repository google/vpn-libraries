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

#include "googlemac/iPhone/Shared/PPN/Krypton/API/PPNHttpFetcher.h"

#import "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcher.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcherService.h"

namespace privacy {
namespace krypton {

// Http request timeout in seconds.
const NSTimeInterval kDefaultRequestTimeout = 30;

PPNHttpFetcher::PPNHttpFetcher()
    : fetcher_service_([[GTMSessionFetcherService alloc] init]),
      request_timeout_(kDefaultRequestTimeout) {}

HttpResponse PPNHttpFetcher::PostJson(const HttpRequest &request) {
  NSString *URLString = [[NSString alloc] initWithUTF8String:request.url().c_str()];
  NSMutableDictionary<NSString *, NSString *> *headers = [[NSMutableDictionary alloc] init];
  for (auto const &[key, value] : request.headers()) {
    NSString *keyString = [[NSString alloc] initWithUTF8String:key.c_str()];
    NSString *valueString = [[NSString alloc] initWithUTF8String:value.c_str()];
    headers[keyString] = valueString;
  }
  NSString *jsonBody = [[NSString alloc] initWithUTF8String:request.json_body().c_str()];

  // Create a Http fetcher with the URL string.
  GTMSessionFetcher *fetcher = [fetcher_service_ fetcherWithURLString:URLString];
  fetcher.callbackQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
  // Add request headers.
  [fetcher setRequestValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
  [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
    [fetcher setRequestValue:value forHTTPHeaderField:key];
  }];
  // Add request body data.
  NSData *bodyData = [jsonBody dataUsingEncoding:NSUTF8StringEncoding];
  fetcher.bodyData = bodyData;

  dispatch_semaphore_t fetchSemaphore = dispatch_semaphore_create(0);
  NSString *__block responseJsonBodyString = nil;
  // Default status code to be 500.
  __block int statusCode = 500;
  [fetcher
      beginFetchWithCompletionHandler:^(NSData *_Nullable receivedData, NSError *_Nullable error) {
        if (error != nil) {
          if ([error.domain isEqual:kGTMSessionFetcherStatusDomain]) {
            statusCode = error.code;
          }
        } else if (receivedData != nil) {
          responseJsonBodyString = [[NSString alloc] initWithData:receivedData
                                                         encoding:NSUTF8StringEncoding];
          statusCode = 200;
        }

        dispatch_semaphore_signal(fetchSemaphore);
      }];
  BOOL semaphoreTimeout =
      dispatch_semaphore_wait(
          fetchSemaphore,
          dispatch_time(DISPATCH_TIME_NOW, (int64_t)(request_timeout_ * NSEC_PER_SEC))) != 0;

  privacy::krypton::HttpResponse response;
  if (semaphoreTimeout) {
    int timeoutStatusCode = 408;
    response.mutable_status()->set_code(timeoutStatusCode);
    NSString *statusMessageString =
        [NSHTTPURLResponse localizedStringForStatusCode:timeoutStatusCode];
    std::string statusMessage = std::string(statusMessageString.UTF8String);
    response.mutable_status()->set_message(statusMessage);
    return response;
  }

  if (responseJsonBodyString != nil) {
    std::string responseJsonBody = std::string(responseJsonBodyString.UTF8String);
    response.set_json_body(responseJsonBody);
  }
  NSString *statusMessageString = [NSHTTPURLResponse localizedStringForStatusCode:statusCode];
  std::string statusMessage = std::string(statusMessageString.UTF8String);
  response.mutable_status()->set_code(statusCode);
  response.mutable_status()->set_message(statusMessage);
  return response;
}

absl::StatusOr<std::string> PPNHttpFetcher::LookupDns(const std::string &hostname) {
  return krypton::utils::ResolveIPAddress(hostname);
}

void PPNHttpFetcher::SetRequestTimeout(NSTimeInterval request_timeout) {
  request_timeout_ = request_timeout;
}

}  // namespace krypton
}  // namespace privacy
