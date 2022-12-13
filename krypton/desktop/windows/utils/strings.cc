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

#include <strsafe.h>
#include <windows.h>

#include <string>

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

std::wstring CharToWstring(absl::string_view str) {
  if (str.empty()) return std::wstring();
  int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(),
                                        static_cast<int>(str.size()), NULL, 0);
  std::wstring dest(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
                      &dest[0], size_needed);
  return dest;
}

std::string WcharToString(const wchar_t* wc) {
  std::wstring wstr(wc);
  return WstringToString(wstr);
}

std::string WstringToString(const std::wstring& wstr) {
  if (wstr.empty()) return std::string();
  int size_needed =
      WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
                          static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
  std::string dest(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
                      &dest[0], size_needed, NULL, NULL);
  return dest;
}

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
