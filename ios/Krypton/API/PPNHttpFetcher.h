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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_API_PPNHTTPFETCHER_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_API_PPNHTTPFETCHER_H_

#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "third_party/absl/status/statusor.h"
#import "third_party/objective_c/gtm_session_fetcher/Source/GTMSessionFetcherService.h"

namespace privacy {
namespace krypton {

class PPNHttpFetcher : public HttpFetcherInterface {
 public:
  PPNHttpFetcher();

  HttpResponse PostJson(const HttpRequest& request) override;

  absl::StatusOr<std::string> LookupDns(const std::string& hostname) override;

  // Sets the request timeout. If not set, the default timeout is used.
  // This method is for test only.
  void SetRequestTimeout(NSTimeInterval request_timeout);

 private:
  GTMSessionFetcherService* fetcher_service_;
  // Request timeout in seconds.
  NSTimeInterval request_timeout_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_API_PPNHTTPFETCHER_H_
