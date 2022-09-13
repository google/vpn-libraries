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

#ifndef PRIVACY_NET_KRYPTON_PAL_TIMER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_TIMER_INTERFACE_H_

#include <functional>
#include <utility>

#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Timer interface that needs to be adapted per platform.
class TimerInterface {
 public:
  TimerInterface() = default;
  virtual ~TimerInterface() = default;

  // Register a call back that needs to be called on timer expiry.
  void RegisterCallback(std::function<void(int)> callback) {
    timer_expiry_cb_ = std::move(callback);
  }

  // Starts a timer for the given duration.
  virtual absl::Status StartTimer(int timer_id, absl::Duration duration) = 0;

  // Cancels a running timer.
  virtual void CancelTimer(int timer_id) = 0;

  // Timer expiry.
  void TimerExpiry(int timer_id) {
    if (timer_expiry_cb_ != nullptr) {
      timer_expiry_cb_(timer_id);
    }
  }

 private:
  std::function<void(int)> timer_expiry_cb_ = nullptr;
};
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_TIMER_INTERFACE_H_
