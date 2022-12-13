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

#include "privacy/net/krypton/desktop/windows/network_monitor.h"

#include "base/init_google.h"
#include "base/logging.h"

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  // Start a NetworkMonitor.
  LOG(INFO) << "Starting NetworkMonitor...";
  privacy::krypton::windows::NetworkMonitor monitor;
  LOG(INFO) << "Created NetworkMonitor";
  auto result = monitor.Start();
  if (!result.ok()) {
    LOG(ERROR) << "Failed to start NetworkMonitor: " << result;
  }

  // NetworkMonitor will log all changes to IP interfaces.
  LOG(INFO) << "NetworkMonitor started. Hit any key to stop...";
  auto ch = getchar();
  monitor.Stop();
}
