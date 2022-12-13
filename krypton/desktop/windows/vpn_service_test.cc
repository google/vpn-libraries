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

#include "privacy/net/krypton/desktop/windows/vpn_service.h"

#include <memory>

#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

// Make sure everything can be instantiated, such that we have implemented all
// abstract methods.
TEST(VpnServiceTest, TestConstructor) {
  VpnService vpn_service;

  // Construct a datapath.
  KryptonConfig config;
  krypton::utils::LooperThread looper("Test Looper");
  MockTimerInterface timer_interface;
  TimerManager timer_manager(&timer_interface);
  std::unique_ptr<DatapathInterface> datapath(
      vpn_service.BuildDatapath(config, &looper, &timer_manager));
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
