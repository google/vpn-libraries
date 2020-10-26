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

#include "privacy/net/krypton/http_header.h"

#include <optional>
#include <string>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

TEST(HttpHeader, TestEmpty) {
  HttpRequest builder;
  auto value = builder.EncodeToJsonObject();
  EXPECT_FALSE(value);
}

TEST(HttpRequestHeaderBuilder, TestUrlAndSomeHeaders) {
  HttpRequest builder;
  builder.MutableHeader()->AddHeader("some_header_name", "some_header_value");
  auto value = builder.EncodeToJsonObject();
  EXPECT_TRUE(value);
  Json::FastWriter writer;
  EXPECT_THAT(
      writer.write(value.value()),
      ::testing::HasSubstr(
          R"string({"headers":{"some_header_name":"some_header_value"}})string"));
}

TEST(HttpResponseHeaderBuilder, TestBasicHeaders) {
  HttpResponse builder;
  Json::Value status;

  status["code"] = 200;
  status["message"] = "OK";

  EXPECT_OK(builder.DecodeFromJsonObject(status));
  EXPECT_EQ(builder.status(), 200);
  EXPECT_EQ(builder.message(), "OK");
}

TEST(HttpResponseHeaderBuilder, TestSomeHeaders) {
  HttpResponse builder;
  Json::Value headers;
  headers["some_header"] = "some_header_value";

  EXPECT_OK(builder.MutableHeader()->DecodeFromJsonObject(headers));
  EXPECT_EQ(builder.message().size(), 0);
  EXPECT_THAT(builder.header().GetHeader("some_header"),
              ::testing::status::IsOkAndHolds("some_header_value"));
}

}  // namespace krypton
}  // namespace privacy
