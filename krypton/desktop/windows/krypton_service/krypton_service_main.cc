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

#include <memory>
#include <string>

#include "base/init_google.h"
#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/crash_reporting/crashpad.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/krypton_service.h"
#include "third_party/absl/log/log.h"

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);
  privacy::krypton::windows::crash_reporting::CrashReporting crash_reporting;
  crash_reporting.StartCrashHandler();
  privacy::krypton::windows::NamedPipeFactory named_pipe_factory;
  privacy::krypton::windows::KryptonService krypton_service(
      &named_pipe_factory);
  absl::Status status = krypton_service.RegisterServiceMain(&krypton_service);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return -1;
  }
  LOG(INFO) << "Exiting Service";
  return 0;
}
