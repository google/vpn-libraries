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

#include "privacy/net/krypton/utils/looper.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace utils {

ABSL_CONST_INIT thread_local LooperThread* current_looper_thread = nullptr;

LooperThread::LooperThread(absl::string_view name)
    : name_(name),
      started_(false),
      lameduck_(false),
      cleaned_up_(false),
      stopped_(false) {
  thread_ = std::make_unique<std::thread>([this] { this->Loop(); });
}

LooperThread::~LooperThread() {
  // Loop() was called, so Stop() and Join(), which will be no-ops if they've
  // already been called.
  Stop();
  Join();

  if (thread_->joinable()) {
    thread_->join();
  }
}

LooperThread* LooperThread::GetCurrentLooper() { return current_looper_thread; }

// Enqueues the given closure to be run on the looper.
bool LooperThread::Post(std::function<void()>&& runnable) {
  {
    absl::MutexLock l(&mutex_);
    if (lameduck_) {
      LOG(ERROR) << "Tried to Post to stopped Looper: " << name_;
      return false;
    }
    queue_.emplace_back(runnable);
  }
  queue_changed_.SignalAll();
  return true;
}

void LooperThread::Stop() {
  LOG(INFO) << "Stop() called for looper: " << name_;
  {
    absl::MutexLock l(&mutex_);
    if (lameduck_) {
      LOG(INFO) << "Looper already in lame-duck mode: " << name_;
      return;
    }
    LOG(INFO) << "Looper entering lame-duck mode: " << name_;
    lameduck_ = true;
  }
  queue_changed_.SignalAll();
}

void LooperThread::Join() {
  // Make sure Join is never called from this Looper's own thread.
  if (std::this_thread::get_id() == thread_->get_id()) {
    LOG(FATAL) << "Join() was called on thread for Looper " << name_;
  }

  LOG(INFO) << "Join() called for looper: " << name_;
  absl::MutexLock l(&mutex_);
  while (!stopped_) {
    LOG(INFO) << "Waiting for looper to be stopped: " << name_;
    stopped_changed_.Wait(&mutex_);
  }
  LOG(INFO) << "Looper is joined: " << name_;
}

std::optional<std::function<void()>> LooperThread::Dequeue() {
  absl::MutexLock l(&mutex_);
  while (queue_.empty()) {
    if (lameduck_) {
      return std::nullopt;
    }
    queue_changed_.Wait(&mutex_);
  }
  auto runnable = std::move(queue_.front());
  queue_.pop_front();
  return runnable;
}

void LooperThread::Loop() {
  current_looper_thread = this;
#ifdef __APPLE__
  // Set a name for the thread to make debugging in Xcode nicer.
  std::string label = "Looper: " + name_;
  pthread_setname_np(label.c_str());
#endif
  {
    absl::MutexLock l(&mutex_);
    if (started_) {
      LOG(ERROR) << "Looper::Loop() was called more than once for " << name_;
      return;
    }
    started_ = true;
  }
  LOG(INFO) << "Starting Looper: " << name_;

  while (true) {
    auto maybe_runnable = Dequeue();
    if (!maybe_runnable) {
      // The looper is in lame-duck mode and the queue is empty.
      LOG(INFO) << "Looper " << name_
                << " is in lameduck mode and the queue is empty. Stopping...";
      break;
    }
    auto runnable = maybe_runnable.value();
    runnable();
  }

  RunAllCleanupHandlers();

  // Mark that the looper is fully stopped.
  {
    absl::MutexLock l(&mutex_);
    stopped_ = true;
  }
  LOG(INFO) << "Stopped Looper: " << name_;
  stopped_changed_.SignalAll();
  current_looper_thread = nullptr;
}

void LooperThread::AddCleanupHandler(std::function<void()> runnable) {
  absl::MutexLock l(&mutex_);
  if (cleaned_up_) {
    LOG(ERROR) << "Tried to AddCleanupHandler too late for Looper: " << name_;
    return;
  }
  cleanup_queue_.emplace_back(runnable);
}

std::optional<std::function<void()>> LooperThread::DequeueCleanupHandler() {
  absl::MutexLock l(&mutex_);
  if (!lameduck_) {
    LOG(FATAL) << "Attempted to dequeue cleanup handler on running looper: "
               << name_;
  }
  if (cleanup_queue_.empty()) {
    cleaned_up_ = true;
    return std::nullopt;
  }
  auto runnable = std::move(cleanup_queue_.front());
  cleanup_queue_.pop_front();
  return runnable;
}

void LooperThread::RunAllCleanupHandlers() {
  LOG(INFO) << "Running cleanup handlers for looper: " << name_;
  while (true) {
    auto maybe_runnable = DequeueCleanupHandler();
    if (!maybe_runnable) {
      return;
    }
    auto runnable = maybe_runnable.value();
    runnable();
  }
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
