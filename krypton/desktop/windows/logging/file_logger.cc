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

#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <ostream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "third_party/absl/algorithm/container.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/time/clock.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {
constexpr uint32_t kLogSizeInBytes = (500 * 1024);    //  0.5 MB
constexpr uint32_t kLogFileSizeInBytes = (5 * 1024);  //  5KB
constexpr char kLogTimeFormat[] = "%Y%m%d_%H%M%E*S.txt";
constexpr uint32_t kNewLineSize = 2;
}  // namespace

FileLogger::FileLogger(const std::wstring& log_directory_path,
                       absl::string_view prefix)
    : log_directory_path_(log_directory_path),
      prefix_(prefix.data(), prefix.size()),
      max_file_size_(kLogFileSizeInBytes),
      max_file_count_(kLogSizeInBytes / kLogFileSizeInBytes),
      current_file_size_(0) {
  ResetLoggerStates();
}

FileLogger::FileLogger(const std::wstring& log_directory_path,
                       absl::string_view prefix, int max_file_size,
                       int max_file_count)
    : log_directory_path_(log_directory_path),
      prefix_(prefix.data(), prefix.size()),
      max_file_size_(max_file_size),
      max_file_count_(max_file_count),
      current_file_size_(0) {
  ResetLoggerStates();
}

std::string FileLogger::CopyLogs() {
  // Logic to copy the logs
  absl::MutexLock l(&mutex_);
  ResetLoggerStates();
  if (sorted_paths_.empty()) {
    return "";
  }

  std::string data;
  data.reserve(max_file_size_ * max_file_count_);

  for (auto& sorted_path : sorted_paths_) {
    AppendFromFile(sorted_path, &data);
  }
  return data;
}

absl::Status FileLogger::Log(absl::string_view log_message) {
  // Logic to Write log in the files
  absl::MutexLock l(&mutex_);
  int total_bytes_to_write = log_message.size();
  if (sorted_paths_.empty()) {
    CreateNewLogFile();
  } else {
    if (current_file_size_ + total_bytes_to_write + kNewLineSize >
        max_file_size_) {
      while (sorted_paths_.size() >= max_file_count_) {
        //  Delete first file
        std::error_code error;
        std::filesystem::remove(sorted_paths_.front(), error);
        sorted_paths_.pop_front();
        if (error) {
          LOG(WARNING) << "[FileLogger] Deletion of file failed with "
                       << error.message();
        }
      }
      CreateNewLogFile();
      current_file_size_ = 0;
    }
  }
  //  Point to the last file
  std::ofstream out_stream;
  out_stream.open(sorted_paths_.back(), std::ios::app);
  out_stream << log_message << std::endl;
  current_file_size_ += total_bytes_to_write;
  // 2 extra bytes for endl;
  current_file_size_ += kNewLineSize;
  out_stream.close();
  return absl::OkStatus();
}

absl::Status FileLogger::ClearLogs() {
  // Logic to clear the logs
  absl::MutexLock l(&mutex_);
  ResetLoggerStates();
  for (std::wstring& file_path : sorted_paths_) {
    std::error_code ec;
    int retval = static_cast<int>(std::filesystem::remove(file_path, ec));
    if (!ec) {
      if (retval == 0) {
        return absl::NotFoundError(
            privacy::krypton::windows::utils::WstringToString(file_path));
      }
    }
  }
  ResetLoggerStates();
  return absl::OkStatus();
}

/** Fetches all log files from the disk and sorts them from the oldest to the
 * newest. */
void FileLogger::ResetLoggerStates() {
  current_file_size_ = 0;
  sorted_paths_.clear();
  sorted_paths_ = ReadSortedPaths();
  if (sorted_paths_.empty()) {
    return;
  }

  //  Get the size of the last (current) file.
  std::ifstream in(sorted_paths_.back().c_str(),
                   std::ifstream::ate | std::ifstream::binary);
  current_file_size_ = in.tellg();
  in.close();
}

/** Reads the Sorted log files from the oldest to the newest. */
std::deque<std::wstring> FileLogger::ReadSortedPaths() {
  std::error_code error;
  std::deque<std::wstring> sub_paths;
  // This directory_iterator constructor: Constructs a directory iterator
  // that refers to the first directory entry of a directory identified by p. If
  // p refers to an non-existing file or not a directory, returns the end
  // iterator and sets ec.
  for (auto& p :
       std::filesystem::directory_iterator(log_directory_path_, error)) {
    sub_paths.push_back(p.path().native());
  }
  if (error) {
    LOG(WARNING) << "[FileLogger] Directory Iterator failed with "
                 << error.message();
    return sub_paths;
  }
  absl::c_sort(sub_paths);
  return sub_paths;
}

void FileLogger::AppendFromFile(const std::wstring& file_path,
                                std::string* output) {
  FILE* debug_file = _wfopen(file_path.c_str(), L"rb");
  std::string message;
  if (debug_file == nullptr) {
    message = "\r\nMissing log file: " +
              privacy::krypton::windows::utils::WstringToString(file_path) +
              "\r\n";
    absl::StrAppend(output, message);
    return;
  }
  fseek(debug_file, 0, SEEK_END);
  int64_t fsize = ftell(debug_file);
  fseek(debug_file, 0, SEEK_SET);
  std::vector<char> chunk(fsize);
  size_t ret_code = fread(chunk.data(), fsize, 1, debug_file);
  if (ret_code != 1) {
    // error handling
    if (feof(debug_file) != 0) {
      message = "\n\nError Reading " +
                privacy::krypton::windows::utils::WstringToString(file_path) +
                ": unexpected end of file\n";
      absl::StrAppend(output, message);
      return;
    }
    message = "\n\nError Reading " +
              privacy::krypton::windows::utils::WstringToString(file_path) +
              "\n";
    absl::StrAppend(output, message);
    return;
  }
  fclose(debug_file);
  absl::StrAppend(output, absl::string_view(chunk.data(), fsize));
}

/**
 * File path would be
 * `%LocalAppData%/Google/GoogleOne/debug/{prefix}{current
 * Now()}`.
 *
 * The @c Now() represents the time when the file is created, and can
 * be used to understand which file is oldest and should be deleted first.
 *
 * Example:
 * NOLINTNEXTLINE
 * %LocalAppData%/Google/GoogleOne/debug/ppn_debug_20220610_213454.2119042.txt
 */
void FileLogger::CreateNewLogFile() {
  std::string log_timestamp =
      absl::FormatTime(kLogTimeFormat, absl::Now(), absl::UTCTimeZone());
  std::wstring new_file_path =
      log_directory_path_ + L"/" +
      privacy::krypton::windows::utils::CharToWstring(prefix_) +
      privacy::krypton::windows::utils::CharToWstring(log_timestamp);
  sorted_paths_.push_back(std::move(new_file_path));
}
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
