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
//
#ifndef PRIVACY_NET_KRYPTON_KRYPTON_CLOCK_H_
#define PRIVACY_NET_KRYPTON_KRYPTON_CLOCK_H_

#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Interface for a Clock object that can be replaced with a fake in tests.
// Necessary since ABSL does not have a clock with a fake that can be used
// in our tests.
class KryptonClock {
 public:
  KryptonClock() = default;

  virtual absl::Time Now() = 0;

  virtual ~KryptonClock() = default;
};

// Real clock that returns the time since epoch.
class RealClock : public KryptonClock {
 public:
  RealClock() = default;

  absl::Time Now() override { return absl::Now(); }
};

// Fake clock for tests.
class FakeClock : public KryptonClock {
 public:
  explicit FakeClock(absl::Time now) { now_ = now; }

  absl::Time Now() override { return now_; }

  // Moves the time returned by Now() by the given duration. Used to mock
  // the passage of time.
  void AdvanceBy(absl::Duration duration) { now_ += duration; }

  // Sets the absl::Time returned when Now() is called.
  void SetNow(absl::Time now) { now_ = now; }

  ~FakeClock() override = default;

 private:
  absl::Time now_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_KRYPTON_CLOCK_H_
