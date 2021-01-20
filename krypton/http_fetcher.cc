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

#include "privacy/net/krypton/http_fetcher.h"

#include <functional>
#include <memory>
#include <string>
#include <thread>  //NOLINT
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

HttpFetcher::~HttpFetcher() { CancelAsync(); }

void HttpFetcher::CancelAsync() {
  // Caller wants to cancel the callback. Mark the callback cancelled.
  if (callback_info_ == nullptr) {
    return;
  }
  absl::MutexLock l(&callback_info_->mutex);
  callback_info_->cancelled = true;
  callback_info_->callback = nullptr;
  LOG(INFO) << "CancelAsync done";
}

void HttpFetcher::PostJsonAsync(
    const HttpRequest& request,
    std::function<void(const HttpResponse&)> callback) {
  if (callback == nullptr) {
    LOG(FATAL) << "callback cannot be null, use |PostJson| instead.";
  }
  LOG(INFO) << "Requesting PostJsonAsync to url: " << request.url();

  callback_info_ = std::make_shared<CallbackInfo>(std::move(callback));

  callback_info_->looper = notification_thread_;
  HttpRequest request_copy(request);
  thread_.Post([this, request] {
    this->PostJsonAsyncInternal(request, callback_info_);
  });
}

void HttpFetcher::PostJsonAsyncInternal(
    const HttpRequest& request, std::shared_ptr<CallbackInfo> callback_info) {
  LOG(INFO) << "Performing PostJsonAsync to url: " << request.url();
  auto response = pal_interface_->PostJson(request);

  // Lock the mutex and check for cancellation before calling the callback.
  {
    absl::MutexLock l(&callback_info->mutex);
    if (callback_info->cancelled) {
      LOG(ERROR)
          << "Callback is cancelled for PostJson, dropping the response.";
      return;
    }
    if (callback_info->callback == nullptr) {
      LOG(INFO) << "Callback is null, not posting the response.";
      return;
    }
    if (notification_thread_ == nullptr) {
      LOG(ERROR) << "No Looper thread found for posting notification.";
      return;
    }
    // Copy the callback as this might result in a deadlock when CancelAsync is
    // called in the same execution stack.
    auto callback = callback_info->callback;
    notification_thread_->Post([callback, response]() { callback(response); });
  }
}

}  // namespace krypton
}  // namespace privacy
