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

#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNTimer.h"

#import <Foundation/Foundation.h>

#include <utility>
#include "base/logging.h"
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"

namespace privacy {
namespace krypton {

absl::Status PPNTimer::StartTimer(int timer_id, absl::Duration duration) {
  absl::WriterMutexLock writer_lock(&timers_lock_);
  if (timer_map_.find(timer_id) != timer_map_.end()) {
    return absl::FailedPreconditionError(absl::StrFormat("timer_id %d already exists.", timer_id));
  }

  dispatch_source_t timer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, callback_queue_);
  if (timer == nullptr) {
    return absl::InternalError("unable to create timer source");
  }

  int64_t start = absl::ToInt64Nanoseconds(duration);
  int64_t leeway = 1 * NSEC_PER_SEC;

  dispatch_source_set_timer(timer, dispatch_walltime(nullptr, start), DISPATCH_TIME_FOREVER,
                            leeway);
  dispatch_source_set_event_handler(timer, ^{
    LOG(INFO) << "Got callback for timer_id " << timer_id;
    CancelTimer(timer_id);
    TimerExpiry(timer_id);
  });
  dispatch_resume(timer);

  if (timer != nullptr) {
    timer_map_[timer_id] = timer;
    LOG(INFO) << "Start timer_id: " << timer_id << " with interval: " << duration;
    return absl::OkStatus();
  }
  return absl::FailedPreconditionError(
      absl::StrCat("Failed to create timer for timer_id: ", timer_id, " with ",
                   absl::FormatDuration(duration), " interval."));
}

void PPNTimer::CancelTimer(int timer_id) {
  absl::WriterMutexLock writer_lock(&timers_lock_);
  if (timer_map_.find(timer_id) == timer_map_.end()) {
    LOG(ERROR) << "Failed to find timer_id to cancel: " << timer_id;
    return;
  }

  dispatch_source_t timer = timer_map_[timer_id];
  LOG(INFO) << "Cancelling timer_id: " << timer_id;
  dispatch_source_cancel(timer);
  timer_map_.erase(timer_id);
  LOG(INFO) << "Cancelled timer_id: " << timer_id;
}

/** Utilities for checking timers count. */
int PPNTimer::TimerCount() {
  absl::ReaderMutexLock reader_lock(&timers_lock_);
  return timer_map_.size();
}

/** If the timer with the given id is present, return whether it is valid; Otherwise return empty
 * optional. */
absl::optional<bool> PPNTimer::IsTimerValid(int timer_id) {
  absl::ReaderMutexLock reader_lock(&timers_lock_);
  if (timer_map_.find(timer_id) != timer_map_.end()) {
    return !dispatch_source_testcancel(timer_map_[timer_id]);
  }
  return absl::nullopt;
}

}  // namespace krypton
}  // namespace privacy
