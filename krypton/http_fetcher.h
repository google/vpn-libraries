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

#ifndef PRIVACY_NET_KRYPTON_HTTP_FETCHER_H_
#define PRIVACY_NET_KRYPTON_HTTP_FETCHER_H_

#include <functional>
#include <memory>
#include <string>

#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

// Http Fetcher class to fetch a single request from the server.
// This can only be used to fetch one request, callers need to create a
// individual |HttpFetcher| for each request.
class HttpFetcher {
 public:
  explicit HttpFetcher(HttpFetcherInterface* pal_interface,
                       utils::LooperThread* looper)
      : pal_interface_(pal_interface),
        thread_("HttpFetcher"),
        notification_thread_(looper) {}

  ~HttpFetcher();

  // Fetcher info that is shared with the running thread and protects
  // the function ptr to ensure that the caller could be deleted without causing
  // a crash to the program.  Unfortunately there is no way for thread to stop
  // executing and this ensures critical sections are
  // protected.
  struct CallbackInfo {
    explicit CallbackInfo(std::function<void(const HttpResponse&)> cb) {
      callback = cb;
      cancelled = false;
    }
    absl::Mutex mutex;
    bool cancelled ABSL_GUARDED_BY(mutex) = false;
    std::function<void(const HttpResponse&)> callback ABSL_GUARDED_BY(mutex);
    utils::LooperThread* looper;  // Not owned.
  };

  // Provides async call back to PostJson, this is a non blocking function.
  // Callback cannot be null.
  void PostJsonAsync(const HttpRequest& request,
                     std::function<void(const HttpResponse&)> callback);

  // Cancel Async processing. This one does not stop the HTTP requests, it stops
  // calling the callback in |PostJsonAsync|.  Applicable only for
  // |PostJsonAsync|.
  void CancelAsync();

 private:
  HttpFetcherInterface* pal_interface_;  // Not owned.

  void PostJsonAsyncInternal(const HttpRequest& request,
                             std::shared_ptr<CallbackInfo> callback_info);

  std::shared_ptr<CallbackInfo> callback_info_;

  utils::LooperThread thread_;
  utils::LooperThread* notification_thread_;
};
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_HTTP_FETCHER_H_
