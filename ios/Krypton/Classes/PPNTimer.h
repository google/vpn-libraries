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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNTIMER_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNTIMER_H_

#import <Foundation/Foundation.h>

#include "privacy/net/krypton/pal/timer_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

class PPNTimer : public TimerInterface {
 public:
  explicit PPNTimer(dispatch_queue_t callback_queue)
      : callback_queue_(callback_queue) {}
  PPNTimer(const PPNTimer& other) = delete;
  PPNTimer(PPNTimer&& other) = delete;

  // Starts a timer for the given duration.
  absl::Status StartTimer(int timer_id, absl::Duration duration) override;

  // Cancels a running timer.
  void CancelTimer(int timer_id) override;

  // Utilities for checking timers count. This is added for tests.
  int TimerCount();

  // If the timer with the given id is present, return whether it is valid.
  // Otherwise return empty optional. This is added for tests.
  absl::optional<bool> IsTimerValid(int timer_id);

 private:
  // Keeps the mapping between timer_id and NSTimer.
  absl::flat_hash_map<int, dispatch_source_t> timer_map_
      ABSL_GUARDED_BY(timers_lock_);

  absl::Mutex timers_lock_;

  dispatch_queue_t callback_queue_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNTIMER_H_
