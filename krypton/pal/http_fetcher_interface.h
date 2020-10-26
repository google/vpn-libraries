// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_PAL_HTTP_FETCHER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_HTTP_FETCHER_INTERFACE_H_

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>  //NOLINT

#include "third_party/absl/strings/string_view.h"
#include "third_party/jsoncpp/value.h"

// This is the native interface that communicates to the platform layer for
// for fetching from a remote server.
// Request will be Json and response is Json.  There are 2 API's that are
// provided a) Sync b) Async
// Caller should keep this object in memory till there are no inflight requests.
// The behavior is undetermined if the object is destroyed with an inflight
// request.
namespace privacy {
namespace krypton {

// Interface class that needs to be implemented per platform.
class HttpFetcherInterface {
 public:
  HttpFetcherInterface() = default;
  virtual ~HttpFetcherInterface() = default;

  // This is a synchronous call that fetches from a remote server.
  // headers: Http headers
  virtual std::string PostJson(absl::string_view url,
                               const Json::Value& headers,
                               const Json::Value& json_body) = 0;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_PAL_HTTP_FETCHER_INTERFACE_H_
