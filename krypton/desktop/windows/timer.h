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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_TIMER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_TIMER_H_

#include <windows.h>

#include <functional>
#include <string>
#include <utility>

#include "privacy/net/krypton/pal/timer_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

// Timer implementation for Windows.
class Timer : public TimerInterface {
 public:
  ~Timer() override;

  static Timer* Get() {
    static auto kInstance = new Timer();
    return kInstance;
  }

  Timer(Timer const&) = delete;
  void operator=(Timer const&) = delete;

  // Starts a timer for the given duration.
  absl::Status StartTimer(int timer_id, absl::Duration duration) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Cancels a running timer.
  void CancelTimer(int timer_id) override ABSL_LOCKS_EXCLUDED(mutex_);

  void TimerCallback(int windows_timer_d) ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the number of active timers. To be used only in tests.
  int NumActiveTimers() const ABSL_LOCKS_EXCLUDED(mutex_);

  // To be used only in tests.
  int GetWindowsTimerId(int timer_id) const ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  Timer();
  void ProcessMessages();

  mutable absl::Mutex mutex_;
  // Maps Krypton Timer ID -> Windows Timer ID
  absl::flat_hash_map<int, UINT_PTR> timer_id_map_ ABSL_GUARDED_BY(mutex_);

  // All timer processing has to happen on the same thread.
  DWORD thread_id_;
  krypton::utils::LooperThread looper_{"Windows Timer Processing Looper"};

  // Call the timer callback on a different thread.
  krypton::utils::LooperThread callback_looper_{
      "Windows Timer Callback Looper"};
};
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_TIMER_H_
