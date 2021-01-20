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

#include <string>

#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {
namespace {
using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

class MockHttpFetcherInterface : public HttpFetcherInterface {
 public:
  MOCK_METHOD(HttpResponse, PostJson, (const HttpRequest&), (override));
};

class HttpFetcherTest : public ::testing::Test {
 public:
  void Callback(const HttpResponse& response) {}
  MockHttpFetcherInterface http_interface_;
  utils::LooperThread looper_thread_{"Test"};
};

TEST_F(HttpFetcherTest, TestBasicPostJson) {
  HttpFetcher fetcher(&http_interface_, &looper_thread_);
  HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  absl::Notification notification;
  HttpResponse response;
  EXPECT_CALL(http_interface_, PostJson(_))
      .WillOnce(
          DoAll(InvokeWithoutArgs(&notification, &absl::Notification::Notify),
                Return(response)));
  fetcher.PostJsonAsync(request,
                        absl::bind_front(&HttpFetcherTest::Callback, this));
  notification.WaitForNotificationWithTimeout(absl::Seconds(3));
}

TEST_F(HttpFetcherTest, CancellationBeforeHttpResponse) {
  HttpFetcher fetcher(&http_interface_, &looper_thread_);
  HttpRequest request;
  request.set_url("http://unknown");
  request.set_json_body("{\"a\":\"b\"}");
  absl::Notification notification;
  HttpResponse response;
  // Delay sending the PostResponse. Wish there was a better way to simulate a
  // delayed response.
  EXPECT_CALL(http_interface_, PostJson(_))
      .WillOnce(
          DoAll(Invoke([]() { absl::SleepFor(absl::Seconds(2)); }),
                InvokeWithoutArgs(&notification, &absl::Notification::Notify),
                Return(response)));
  fetcher.PostJsonAsync(request,
                        absl::bind_front(&HttpFetcherTest::Callback, this));
  fetcher.CancelAsync();
  notification.WaitForNotification();
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
