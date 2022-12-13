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

#include "privacy/net/krypton/desktop/windows/timer.h"

#include <windows.h>

#include <functional>
#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/blocking_counter.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace windows {

// Sending this message to the timer thread will cause it to yield long enough
// to process pending work.
constexpr int kInterruptMessage = WM_USER + 1;

VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT_PTR windows_timer_id,
                        DWORD time) {
  LOG(INFO) << "Callback for windows_timer_id: " << windows_timer_id;
  // SetTimer dispatches a message after intervals of set duration. eg. every
  // 10s. Hence timer needs to be killed when callback is called.
  KillTimer(NULL, windows_timer_id);

  Timer::Get()->TimerCallback(windows_timer_id);
}

void Timer::ProcessMessages() {
  LOG(INFO) << "Processing WM_TIMER messages.";
  MSG msg = {};
  while (GetMessage(&msg, nullptr, 0, 0) >= 0) {
    switch (msg.message) {
      case WM_TIMER:
        LOG(INFO)
            << "Got a timer message on the background thread for timer id: "
            << msg.wParam;
        break;
      case kInterruptMessage:
        LOG(INFO) << "Interrupting WM_TIMER processing.";
        looper_.Post([this] { ProcessMessages(); });
        return;
      default:
        LOG(INFO) << "Unknown message on WM_TIMER processing thread: "
                  << msg.message;
    }
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  LOG(INFO) << "Shutting down WM_TIMER message processing.";
}

Timer::Timer() {
  LOG(INFO) << "Starting WM_TIMER processing thread.";
  absl::BlockingCounter counter{1};
  looper_.Post([this, &counter]() {
    thread_id_ = GetCurrentThreadId();

    // Call PeekMessage to set up the message queue for the thread.
    MSG msg;
    PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

    // Signal that the thread is ready.
    counter.DecrementCount();

    ProcessMessages();
  });
  counter.Wait();
  LOG(INFO) << "WM_TIMER processing thread id: " << thread_id_;
}

Timer::~Timer() {
  LOG(INFO) << "Stopping WM_TIMER message processing thread.";
  looper_.Post([]() { PostQuitMessage(0); });
  PostThreadMessage(thread_id_, kInterruptMessage, 0, 0);
}

void Timer::TimerCallback(int windows_timer_id) {
  int timer_id = -1;
  {
    absl::MutexLock l(&mutex_);

    for (auto const& entry : timer_id_map_) {
      if (entry.second == windows_timer_id) {
        timer_id = entry.first;
        break;
      }
    }
    if (timer_id == -1) {
      LOG(WARNING) << "No Timer found for windows_timer_id: "
                   << windows_timer_id;
      return;
    }
    timer_id_map_.erase(timer_id);
  }
  callback_looper_.Post([this, timer_id]() { TimerExpiry(timer_id); });
}

absl::Status Timer::StartTimer(int timer_id, absl::Duration duration) {
  LOG(INFO) << "Starting Timer for timer_id: " << timer_id
            << " and duration: " << duration;

  // Get the timer on the special thread.
  UINT_PTR windows_timer_id = 0;
  DWORD windows_timer_error = 0;
  absl::BlockingCounter counter{1};
  LOG(INFO) << "Posting to timer thread";
  bool posted = looper_.Post([&windows_timer_id, &windows_timer_error, duration,
                              &counter]() {
    auto millis = static_cast<uint64_t>(absl::ToInt64Milliseconds(duration));
    windows_timer_id = SetTimer(NULL, 0, millis, &TimerProc);
    if (windows_timer_id == 0) {
      windows_timer_error = GetLastError();
    }
    counter.DecrementCount();
  });
  if (posted) {
    // Interrupt message processing so that it processes our request.
    PostThreadMessage(thread_id_, kInterruptMessage, 0, 0);
    counter.Wait();
  } else {
    LOG(ERROR) << "Unable to create timer.";
    return absl::CancelledError("Timer thread is stopped.");
  }

  if (windows_timer_id == 0) {
    return utils::GetStatusForError("Unable to create timer",
                                    windows_timer_error);
  }

  LOG(INFO) << "Started Timer for timer_id: " << timer_id
            << " with windows_timer_id: " << windows_timer_id;

  absl::MutexLock l(&mutex_);

  timer_id_map_[timer_id] = windows_timer_id;
  return absl::OkStatus();
}

void Timer::CancelTimer(int timer_id) {
  absl::MutexLock l(&mutex_);
  auto result = timer_id_map_.find(timer_id);
  if (result == timer_id_map_.end()) {
    LOG(WARNING) << "No Timer found for timer_id: " << timer_id;
    return;
  }

  LOG(INFO) << "Cancelling Timer for timer_id: " << timer_id
            << " with windows_timer_id:" << result->second;

  auto windows_thread_id = result->second;
  absl::BlockingCounter counter{1};
  bool posted = looper_.Post([windows_thread_id, &counter]() {
    if (!KillTimer(NULL, windows_thread_id)) {
      auto status =
          utils::GetStatusForError("Unable to kill timer", GetLastError());
      LOG(ERROR) << "Unable to kill timer: " << status;
    }
    counter.DecrementCount();
  });
  if (posted) {
    // Interrupt message processing so that it processes our request.
    PostThreadMessage(thread_id_, kInterruptMessage, 0, 0);
    counter.Wait();
    LOG(INFO) << "Cancelled Timer for timer_id: " << timer_id
              << " with windows_timer_id:" << result->second;
  } else {
    LOG(ERROR) << "Cannot cancel timer, because timer thread is stopped.";
  }
  timer_id_map_.erase(timer_id);
}

// Returns the number of active timers.
int Timer::NumActiveTimers() const {
  absl::MutexLock l(&mutex_);
  return timer_id_map_.size();
}

int Timer::GetWindowsTimerId(int timer_id) const {
  absl::MutexLock l(&mutex_);
  auto result = timer_id_map_.find(timer_id);
  if (result == timer_id_map_.end()) {
    return -1;
  }
  return result->second;
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
