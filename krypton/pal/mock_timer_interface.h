// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_PAL_MOCK_TIMER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_MOCK_TIMER_INTERFACE_H_

#include "privacy/net/krypton/pal/timer_interface.h"
#include "testing/base/public/gmock.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Mock for |TimerInterface|
class MockTimerInterface : public TimerInterface {
 public:
  MOCK_METHOD(absl::Status, StartTimer, (int, absl::Duration), (override));
  MOCK_METHOD(void, CancelTimer, (int), (override));
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_PAL_MOCK_TIMER_INTERFACE_H_
