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

#ifndef PRIVACY_NET_KRYPTON_TIMER_MANAGER_H_
#define PRIVACY_NET_KRYPTON_TIMER_MANAGER_H_

#include <atomic>
#include <functional>
#include <map>
#include <string>

#include "privacy/net/krypton/pal/timer_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Manages timers for Krypton. The actual timer is delegated to the platform
// layer. This class only keeps the outstanding timers.
// Thread-safe implementation.
class TimerManager {
 public:
  explicit TimerManager(TimerInterface* timer_interface);
  ~TimerManager();

  using TimerCb = std::function<void()>;

  // Starts a timer that takes in a callback that is called on timer expiry.
  // Returns a timer_id that could be used to cancel a pending timer.
  absl::StatusOr<int> StartTimer(absl::Duration duration, TimerCb callback,
                                 absl::string_view label)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Cancels a pending timer by id. No op if the timer id does not exist.
  void CancelTimer(int timer_id) ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the number of active timers.
  int NumActiveTimers() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return timer_map_.size();
  }

 private:
  struct TimerDetails {
    std::string label;
    TimerCb timer_cb;
  };

  void TimerExpiry(int timer_id);

  TimerInterface* timer_interface_;  // Not owned.
  mutable absl::Mutex mutex_;
  std::map<int, TimerDetails> timer_map_ ABSL_GUARDED_BY(mutex_);
  std::atomic_int timer_id_counter_ = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_TIMER_MANAGER_H_
