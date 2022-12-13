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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_FILE_LOGGER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_FILE_LOGGER_H_

#include <deque>
#include <memory>
#include <string>
#include <utility>

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

/** Logger that writes logs into a file on the disk. */
class FileLogger {
 public:
  /*
   * Creates a FileLogger.
   *
   * log_directory_path - Directory where the logs are stored as files.
   * prefix - Prefix for the file name.
   */
  explicit FileLogger(const std::wstring& log_directory_path,
                      absl::string_view prefix);

  FileLogger(const std::wstring& log_directory_path, absl::string_view prefix,
             int max_file_size, int max_file_count);

  ~FileLogger() = default;
  FileLogger(const FileLogger&) = delete;
  FileLogger& operator=(const FileLogger&) = delete;

  /** Logs a string to the local file */
  absl::Status Log(absl::string_view log_message) ABSL_LOCKS_EXCLUDED(mutex_);

  /** Gets the log for PPN if there are any. */
  std::string CopyLogs() ABSL_LOCKS_EXCLUDED(mutex_);

  /**
   * Clears the log from the previous session.
   *
   * This method should be called when starting a new session.
   */
  absl::Status ClearLogs() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  std::wstring log_directory_path_;

  /** Prefix for the log file name  */
  std::string prefix_;

  /** The maximium size of a single log file */
  int max_file_size_;

  /** The maximum number of log files. */
  int max_file_count_;

  void CreateNewLogFile() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void ResetLoggerStates() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  std::deque<std::wstring> ReadSortedPaths();

  void AppendFromFile(const std::wstring& file_path, std::string* output);

  absl::Mutex mutex_;

  /**
   * An array of file paths that each contains a small piece of all logs.
   *
   * This array is sorted by the timestamp of the file creation, from the oldest
   * to newest.
   */
  std::deque<std::wstring> sorted_paths_ ABSL_GUARDED_BY(mutex_);

  /** The size of the current log file in bytes */
  int current_file_size_ ABSL_GUARDED_BY(mutex_);
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOGGING_FILE_LOGGER_H_
