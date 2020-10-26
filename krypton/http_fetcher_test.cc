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
  MOCK_METHOD(std::string, PostJson,
              (absl::string_view, const Json::Value&, const Json::Value&),
              (override));
};

class HttpFetcherTest : public ::testing::Test {
 public:
  void Callback(absl::string_view response) {}
  MockHttpFetcherInterface http_interface_;
  utils::LooperThread looper_thread_{"Test"};
};

TEST_F(HttpFetcherTest, TestBasicPostJson) {
  HttpFetcher fetcher(&http_interface_, &looper_thread_);
  Json::Value json_body;
  json_body["a"] = "b";
  absl::Notification notification;
  EXPECT_CALL(http_interface_, PostJson(_, _, _))
      .WillOnce(
          DoAll(InvokeWithoutArgs(&notification, &absl::Notification::Notify),
                Return("some value")));
  fetcher.PostJsonAsync("http://unknown", Json::Value::null, json_body,
                        absl::bind_front(&HttpFetcherTest::Callback, this));
  notification.WaitForNotificationWithTimeout(absl::Seconds(3));
}

TEST_F(HttpFetcherTest, CancellationBeforeHttpResponse) {
  HttpFetcher fetcher(&http_interface_, &looper_thread_);
  Json::Value json_body;
  json_body["a"] = "b";
  absl::Notification notification;
  // Delay sending the PostResponse. Wish there was a better way to simulate a
  // delayed response.
  EXPECT_CALL(http_interface_, PostJson(_, _, _))
      .WillOnce(
          DoAll(Invoke([]() { absl::SleepFor(absl::Seconds(2)); }),
                InvokeWithoutArgs(&notification, &absl::Notification::Notify),
                Return("some value")));
  fetcher.PostJsonAsync("http://unknown", Json::Value::null, json_body,
                        absl::bind_front(&HttpFetcherTest::Callback, this));
  fetcher.CancelAsync();
  notification.WaitForNotification();
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
