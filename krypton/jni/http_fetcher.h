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

#ifndef PRIVACY_NET_KRYPTON_JNI_HTTP_FETCHER_H_
#define PRIVACY_NET_KRYPTON_JNI_HTTP_FETCHER_H_

#include <string>

#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {
namespace jni {

// JNI implementation for the HttpFetcher.
class HttpFetcher : public HttpFetcherInterface {
 public:
  HttpFetcher() = default;
  ~HttpFetcher() final = default;

  // Fetches the content from a remote server. This is a blocking call.
  HttpResponse PostJson(const HttpRequest& request) override;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_HTTP_FETCHER_H_
