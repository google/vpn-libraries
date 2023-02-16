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

#include <string>
#include <vector>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

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

}  // namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
