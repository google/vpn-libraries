/*
 * Copyright (C) 2022 Google Inc.
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

#include "privacy/net/krypton/desktop/windows/logging/file_logger.h"

#include <string>

#include "privacy/net/krypton/desktop/windows/utils/file_utils.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "testing/base/public/mock-log.h"
#include "third_party/absl/base/log_severity.h"

using ::testing::_;
using ::testing::ScopedMockLog;

namespace privacy {
namespace krypton {
namespace windows {

#ifdef _WIN32
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

class FileLoggerTest : public ::testing::Test {
 protected:
  std::wstring debug_directory_ =
      privacy::krypton::windows::utils::CharToWstring(testing::TempDir());
};

TEST_F(FileLoggerTest, SingleLog) {
  ScopedMockLog log(testing::kDoNotCaptureLogsYet);
  EXPECT_CALL(
      log,
      Log(base_logging::WARNING, _,
          testing::HasSubstr("[FileLogger] Directory Iterator failed with")))
      .Times(0);
  log.StartCapturingLogs();
  FileLogger file_logger(debug_directory_, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("My First Log");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("My First Log" EOL, log_data);
}

TEST_F(FileLoggerTest, CorrectOrderOfLogs) {
  FileLogger file_logger(debug_directory_, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("My First Log");
  log_result = file_logger.Log("My Second Log");
  log_result = file_logger.Log("My Third Log");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("My First Log" EOL "My Second Log" EOL "My Third Log" EOL,
            log_data);
}

TEST_F(FileLoggerTest, CopyLogEmptyStringLogWithNoLog) {
  FileLogger file_logger(debug_directory_, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("", log_data);
}

TEST_F(FileLoggerTest, LogClearLogCopyLog) {
  FileLogger file_logger(debug_directory_, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("My First Log");
  clear_log_result = file_logger.ClearLogs();
  log_result = file_logger.Log("My Second Log");
  log_result = file_logger.Log("My Third Log");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("My Second Log" EOL "My Third Log" EOL, log_data);
}

TEST_F(FileLoggerTest, CopyLogAfterClearingLog) {
  FileLogger file_logger(debug_directory_, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("My First Log");
  clear_log_result = file_logger.ClearLogs();
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("", log_data);
}

TEST_F(FileLoggerTest, ExceedingMaxLogSizeDeleteTheOldestFile) {
  FileLogger file_logger(debug_directory_, "Log", 5, 3);
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("Foo");
  log_result = file_logger.Log("Bar");
  log_result = file_logger.Log("Baz");
  log_result = file_logger.Log("Lux");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("Bar" EOL "Baz" EOL "Lux" EOL, log_data);
}

TEST_F(FileLoggerTest, TestingRollOver) {
  FileLogger file_logger(debug_directory_, "Log", 5, 10);
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("full");
  log_result = file_logger.Log("more");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("full" EOL "more" EOL, log_data);
}

TEST_F(FileLoggerTest, EmptyDirectoryClearLogsReturnsOk) {
  ScopedMockLog log(testing::kDoNotCaptureLogsYet);
  EXPECT_CALL(
      log,
      Log(base_logging::WARNING, _,
          testing::HasSubstr("[FileLogger] Directory Iterator failed with")))
      .Times(testing::AtLeast(1));
  log.StartCapturingLogs();
  FileLogger file_logger(L"", "Log");
  auto clear_log_result = file_logger.ClearLogs();
  EXPECT_THAT(clear_log_result, ::testing::status::IsOk());
}

TEST_F(FileLoggerTest, NonExistentDirectoryNoLogsAreWritten) {
  ScopedMockLog log(testing::kDoNotCaptureLogsYet);
  EXPECT_CALL(
      log,
      Log(base_logging::WARNING, _,
          testing::HasSubstr("[FileLogger] Directory Iterator failed with")))
      .Times(testing::AtLeast(1));
  log.StartCapturingLogs();
  FileLogger file_logger(L"/tmp/vpn_no_log_folder", "Log");
  auto log_result = file_logger.Log("My First Log");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("", log_data);
}

// Keep this test in the last as new directory is created
TEST_F(FileLoggerTest, CorrectOrderOfLogsWithFolderHavingSpecialCharacter) {
  std::wstring debug_directory_japanese = debug_directory_ + L"/" + L"要らない";
  (void)privacy::krypton::windows::utils::CreateDirectoryRecursively(
      debug_directory_japanese);
  FileLogger file_logger(debug_directory_japanese, "Log");
  auto clear_log_result = file_logger.ClearLogs();
  auto log_result = file_logger.Log("My First Log");
  log_result = file_logger.Log("My Second Log");
  log_result = file_logger.Log("My Third Log");
  std::string log_data = file_logger.CopyLogs();
  EXPECT_EQ("My First Log" EOL "My Second Log" EOL "My Third Log" EOL,
            log_data);
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
