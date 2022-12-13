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

// On Windows, define NOMINMAX prior to including Crashpad to avoid
// unwanted definitions of macros MIN and MAX from WinAPI
#define NOMINMAX
#include "privacy/net/krypton/desktop/windows/crash_reporting/crashpad.h"

#include <windows.h>

#include <filesystem>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/file_utils.h"
#include "third_party/crashpad/crashpad/client/crash_report_database.h"
#include "third_party/crashpad/crashpad/client/crashpad_client.h"
#include "third_party/crashpad/crashpad/client/settings.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace crash_reporting {

#define STRINGIFY(arg) #arg
#define STR(arg) STRINGIFY(arg)

std::wstring CrashReporting::GetExecutableDirectoryPath() {
  wchar_t googleone_executable_temp_buffer[MAX_PATH];
  GetModuleFileName(NULL, googleone_executable_temp_buffer, MAX_PATH);
  std::wstring::size_type pos =
      std::wstring(googleone_executable_temp_buffer).find_last_of(L"\\/");
  return std::wstring(googleone_executable_temp_buffer).substr(0, pos);
}

bool CrashReporting::StartCrashHandler() {
  const char kCrashFolderName[] = "crash_krypton_service";
  const char kCrashpadHandlerExecutable[] = "crashpad_handler.exe";
  const char kProductName[] = "VPN_By_Google_One_Desktop_Krypton_Service";
  const char kCrashReportStagingUrl[] =
      "https://clients2.google.com/cr/staging_report";
  const char kCrashReportProdUrl[] = "https://clients2.google.com/cr/report";

  std::map<std::string, std::string> annotations;
  std::vector<std::string> arguments;
  crashpad::CrashpadClient client;
  bool rc;

  auto local_app_data_dir = utils::CreateLocalAppDataPath();
  auto crash_db_path = local_app_data_dir.value() / kCrashFolderName;
  utils::CreateDirectoryRecursively(crash_db_path);

  auto googleone_directory_path_temp_buffer = GetExecutableDirectoryPath();
  std::filesystem::path googleone_directory_path(
      googleone_directory_path_temp_buffer);
  auto crash_handler_path =
      googleone_directory_path / kCrashpadHandlerExecutable;

  std::string build_env = STR(BUILD_ENV);

  std::string url(kCrashReportProdUrl);
  if (build_env == "dev") {
    url = kCrashReportStagingUrl;
  }
  annotations["prod"] = kProductName;
  annotations["ver"] = STR(APP_VERSION);

  base::FilePath db(crash_db_path);
  base::FilePath handler(crash_handler_path);

  std::unique_ptr<crashpad::CrashReportDatabase> database =
      crashpad::CrashReportDatabase::Initialize(db);

  if (database == nullptr || database->GetSettings() == NULL) {
    LOG(ERROR) << "Database Initialization Failed";
    return false;
  }

  database->GetSettings()->SetUploadsEnabled(true);
  rc = client.StartHandler(handler, db, db, url, annotations, arguments,
                           /*restartable=*/true, /*asynchronous_start=*/true);
  if (rc == false) {
    LOG(ERROR) << "Crashpad client : Start Handler Failed";
    return false;
  }
  return true;
}
}  //  namespace crash_reporting
}  //  namespace windows
}  //  namespace krypton
}  //  namespace privacy
