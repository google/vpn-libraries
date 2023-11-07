// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/utils/json_util.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/common/proto/beryllium.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::ElementsAre;
using ::testing::EqualsProto;
using ::testing::status::StatusIs;

TEST(JsonUtilTest, JsonToStringString) {
  nlohmann::json json_obj;
  json_obj["test"] = "abc";
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":"abc"})string");
}

TEST(JsonUtilTest, JsonToStringArray) {
  nlohmann::json json_obj;
  json_obj["test"] = nlohmann::json::array({"a", "b", "c"});
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":["a","b","c"]})string");
}

TEST(JsonUtilTest, JsonToStringBoolean) {
  nlohmann::json json_obj;
  json_obj["test"] = true;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":true})string");
}

TEST(JsonUtilTest, JsonToStringNull) {
  nlohmann::json json_obj;
  nlohmann::json json_subobj;
  json_obj["test"] = json_subobj;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":null})string");
}

TEST(JsonUtilTest, JsonToStringSubobj) {
  nlohmann::json json_obj;
  nlohmann::json json_subobj;
  json_subobj["test2"] = "abc";
  json_obj["test1"] = json_subobj;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test1":{"test2":"abc"}})string");
}

TEST(JsonUtilTest, JsonToStringUnsignedInteger) {
  nlohmann::json json_obj;
  json_obj["test"] = 123;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":123})string");
}

TEST(JsonUtilTest, JsonToStringInteger) {
  nlohmann::json json_obj;
  json_obj["test"] = -123;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":-123})string");
}

TEST(JsonUtilTest, JsonToStringFloat) {
  nlohmann::json json_obj;
  json_obj["test"] = 4.56;
  auto json_str = JsonToString(json_obj);
  EXPECT_EQ(json_str, R"string({"test":4.56})string");
}

TEST(JsonUtilTest, JsonToStringMultipleItems) {
  nlohmann::json json_obj;
  json_obj["test1"] = "abc";
  json_obj["test2"] = 123;
  json_obj["test3"] = true;
  auto json_str = JsonToString(json_obj);
  EXPECT_FALSE(json_str.empty());
  EXPECT_EQ(json_str,
            R"string({"test1":"abc","test2":123,"test3":true})string");
}

TEST(JsonUtilTest, JsonToStringBadCharacter) {
  nlohmann::json json_obj;
  json_obj["test1"] = "x\xA9y";
  auto json_str = JsonToString(json_obj);
  // The bad character is ignored and left out of the conversion
  EXPECT_EQ(json_str, R"string({"test1":"xy"})string");
}

TEST(JsonUtilTest, JsonToStringNullObject) {
  nlohmann::json json_obj;
  auto json_str = JsonToString(json_obj);
  EXPECT_TRUE(json_str.empty());
}

TEST(JsonUtilTest, StringToJsonString) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : "abc"
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_string());
  EXPECT_EQ(json["test"], "abc");
}

TEST(JsonUtilTest, StringToJsonArray) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : ["a","b","c"]
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_array());
  EXPECT_EQ(json["test"], std::vector<std::string>({"a", "b", "c"}));
}

TEST(JsonUtilTest, StringToJsonBoolean) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : true
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_boolean());
  EXPECT_TRUE(json["test"]);
}

TEST(JsonUtilTest, StringToJsonNull) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : null
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_null());
}

TEST(JsonUtilTest, StringToJsonSubobj) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test1" : {"test2" : "abc"}
   })string"));
  ASSERT_TRUE(json.contains("test1"));
  ASSERT_TRUE(json["test1"].contains("test2"));
  EXPECT_EQ(json["test1"]["test2"], "abc");
}

TEST(JsonUtilTest, StringToJsonUnsignedInteger) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : 123
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_number_integer());
  ASSERT_TRUE(json["test"].is_number_unsigned());
  EXPECT_EQ(json["test"], 123);
}

TEST(JsonUtilTest, StringToJsonInteger) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : -123
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_number_integer());
  ASSERT_FALSE(json["test"].is_number_unsigned());
  EXPECT_EQ(json["test"], -123);
}

TEST(JsonUtilTest, StringToJsonFloat) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test" : 4.56
   })string"));
  ASSERT_TRUE(json.contains("test"));
  ASSERT_TRUE(json["test"].is_number_float());
  EXPECT_EQ(json["test"], 4.56);
}

TEST(JsonUtilTest, StringToJsonMultipleItems) {
  ASSERT_OK_AND_ASSIGN(auto json, StringToJson(R"string({
      "test1" : "abc",
      "test2" : 123,
      "test3" : true
   })string"));
  ASSERT_TRUE(json.contains("test1"));
  ASSERT_TRUE(json["test1"].is_string());
  EXPECT_EQ(json["test1"], "abc");
  ASSERT_TRUE(json.contains("test2"));
  ASSERT_TRUE(json["test2"].is_number_integer());
  ASSERT_TRUE(json["test2"].is_number_unsigned());
  EXPECT_EQ(json["test2"], 123);
  ASSERT_TRUE(json.contains("test3"));
  ASSERT_TRUE(json["test3"].is_boolean());
  EXPECT_EQ(json["test3"], true);
}

TEST(JsonUtilTest, StringToJsonEmptyString) {
  EXPECT_THAT(StringToJson(""), StatusIs(absl::StatusCode::kInternal));
}

TEST(JsonUtilTest, StringToJsonTrailingComma) {
  EXPECT_THAT(StringToJson(R"string({
      "test" : "abc",
   })string"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(JsonUtilTest, StringToJsonMissingBrackets) {
  EXPECT_THAT(StringToJson(R"string(
      "test" : "abc"
   )string"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(JsonUtilTest, StringToJsonExtraBracket) {
  EXPECT_THAT(StringToJson(R"string({}
      "test" : "abc"
   }})string"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(JsonUtilTest, JsonGetInt64IgnoresEmptyField) {
  std::string json_key = "test";
  nlohmann::json json_obj;

  ASSERT_OK_AND_ASSIGN(std::optional<int64_t> int_value,
                       JsonGetInt64(json_obj, json_key));

  EXPECT_FALSE(int_value);
}

TEST(JsonContains, JsonGetInt64FailsOnTheWrongType) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = "foo";

  ASSERT_THAT(JsonGetInt64(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonContains, JsonGetInt64ReturnsInt64) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = 123;

  ASSERT_OK_AND_ASSIGN(std::optional<int64_t> int_value,
                       JsonGetInt64(json_obj, json_key));

  ASSERT_TRUE(int_value);
  EXPECT_EQ(*int_value, 123);
}

TEST(JsonUtilTest, JsonGetStringIgnoresEmptyField) {
  nlohmann::json json_obj;
  std::string json_key = "test";

  ASSERT_OK_AND_ASSIGN(std::optional<std::string> value,
                       JsonGetString(json_obj, json_key));

  EXPECT_FALSE(value);
}

TEST(JsonUtilTest, JsonGetStringFailsOnTheWrongType) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = 0;

  ASSERT_THAT(JsonGetString(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetStringReturnsString) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = "foo";

  ASSERT_OK_AND_ASSIGN(std::optional<std::string> value,
                       JsonGetString(json_obj, json_key));

  ASSERT_TRUE(value);
  ASSERT_EQ(*value, "foo");
}

TEST(JsonUtilTest, JsonGetBytesIgnoresEmptyField) {
  nlohmann::json json_obj;
  std::string json_key = "test";

  ASSERT_OK_AND_ASSIGN(std::optional<std::string> value,
                       JsonGetBytes(json_obj, json_key));

  EXPECT_FALSE(value);
}

TEST(JsonUtilTest, JsonGetBytesFailsOnTheWrongType) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = 0;

  ASSERT_THAT(JsonGetBytes(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetBytesFailsWithFieldNotBase64Encoded) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = ":foo:";

  ASSERT_THAT(JsonGetBytes(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetBytesReturnsBytes) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = "Zm9v";

  ASSERT_OK_AND_ASSIGN(std::optional<std::string> value,
                       JsonGetBytes(json_obj, json_key));

  ASSERT_TRUE(value);
  ASSERT_EQ(*value, "foo");
}

TEST(JsonUtilTest, JsonGetStringArrayIgnoresEmptyField) {
  std::string json_key = "test";
  nlohmann::json json_obj;

  ASSERT_OK_AND_ASSIGN(std::optional<std::vector<std::string>> value,
                       JsonGetStringArray(json_obj, json_key));

  EXPECT_FALSE(value);
}

TEST(JsonUtilTest, JsonGetStringArrayIgnoresFieldNotArray) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = "foo";

  ASSERT_THAT(JsonGetStringArray(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetStringArrayIgnoresArrayOfWrongType) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = nlohmann::json::array({0, 1});

  ASSERT_THAT(JsonGetStringArray(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetStringArrayReturnsStringArray) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = nlohmann::json::array({"foo", "bar"});

  ASSERT_OK_AND_ASSIGN(std::optional<std::vector<std::string>> value,
                       JsonGetStringArray(json_obj, json_key));

  ASSERT_TRUE(value);
  EXPECT_THAT(*value, ElementsAre("foo", "bar"));
}

TEST(JsonUtilTest, JsonGetIpRangeArrayIgnoresEmptyField) {
  std::string json_key = "test";
  nlohmann::json json_obj;

  ASSERT_OK_AND_ASSIGN(
      std::optional<std::vector<net::common::proto::IpRange>> value,
      JsonGetIpRangeArray(json_obj, json_key));

  EXPECT_FALSE(value);
}

TEST(JsonUtilTest, JsonGetIpRangeArrayIgnoresFieldNotArray) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  nlohmann::json ipv4_range;
  ipv4_range["ipv4_range"] = "127.0.0.1";
  json_obj[json_key] = ipv4_range;

  ASSERT_THAT(JsonGetIpRangeArray(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetIpRangeArrayIgnoresArrayOfWrongType) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  json_obj[json_key] = nlohmann::json::array({0, 1});

  ASSERT_THAT(JsonGetIpRangeArray(json_obj, json_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetIpRangeArrayCopiesIpRangeArray) {
  std::string json_key = "test";
  nlohmann::json json_obj;
  nlohmann::json ipv4_range;
  nlohmann::json ipv6_range;
  ipv4_range["ipv4_range"] = "127.0.0.1";
  ipv6_range["ipv6_range"] = "fe80::1";
  json_obj[json_key] = nlohmann::json::array({ipv4_range, ipv6_range});

  ASSERT_OK_AND_ASSIGN(
      std::optional<std::vector<net::common::proto::IpRange>> value,
      JsonGetIpRangeArray(json_obj, json_key));

  ASSERT_TRUE(value);
  net::common::proto::IpRange ipv4_range_proto =
      ParseTextProtoOrDie(R"pb(ipv4_range: "127.0.0.1")pb");
  net::common::proto::IpRange ipv6_range_proto =
      ParseTextProtoOrDie(R"pb(ipv6_range: "fe80::1")pb");
  EXPECT_THAT(*value, ElementsAre(EqualsProto(ipv4_range_proto),
                                  EqualsProto(ipv6_range_proto)));
}

}  // namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
