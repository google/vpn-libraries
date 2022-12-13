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

#include "privacy/net/krypton/desktop/windows/utils/strings.h"

#include <string>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {
namespace {

TEST(StringUtilsTest, TestCharToWstring) {
  std::wstring w = L"some string";
  EXPECT_EQ(w, CharToWstring("some string"));

  w = L"string with おはよう";
  EXPECT_EQ(w, CharToWstring("string with おはよう"));

  w = L"string with 😂";
  EXPECT_EQ(w, CharToWstring("string with 😂"));
}

TEST(StringUtilsTest, TestWcharToString) {
  std::string str = "some string";
  EXPECT_EQ(str, WcharToString(L"some string"));

  str = "string with おはよう";
  EXPECT_EQ(str, WcharToString(L"string with おはよう"));

  str = "string with 😂";
  EXPECT_EQ(str, WcharToString(L"string with 😂"));
}

}  // namespace
}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
