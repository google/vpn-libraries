// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "privacy/net/krypton/signal_handler.h"

#include <csignal>

#include "base/logging.h"
#include "third_party/absl/base/call_once.h"
#include "third_party/absl/base/macros.h"

namespace privacy {
namespace krypton {
namespace {

// The list of signals to treat as crashes.
const int kExceptionSignals[] = {SIGSEGV, SIGABRT, SIGFPE,
                                 SIGILL,  SIGBUS,  SIGTRAP};

// The handlers that were installed before Install was called.
struct sigaction old_handlers[ARRAYSIZE(kExceptionSignals)];

// A flag to make sure we only install our own handlers once.
absl::once_flag install_once_;

// Interface to call back when an exception signal was caught.
KryptonNotificationInterface* notification_;  // Not owned.

}  // namespace

// Gets called whenever one of the handled signals is raised.
void SignalHandler::OnSignal(int signal, siginfo_t* /* info */,
                             void* /* unused */) {
  LOG(INFO) << "SignalHandler::OnSignal() was called for signal " << signal;
  if (notification_ != nullptr) {
    notification_->Crashed();
  }

  // Re-install the old handlers.
  for (int i = 0; i < ABSL_ARRAYSIZE(kExceptionSignals); ++i) {
    sigaction(kExceptionSignals[i], &old_handlers[i], nullptr);
  }

  // Re-raise the signal.
  raise(signal);
}

// Installs our custom signal handlers to get notified of exceptions.
void SignalHandler::Install() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  // Mask every signal except the one being handled.
  sigemptyset(&sa.sa_mask);
  for (auto signal : kExceptionSignals) {
    sigaddset(&sa.sa_mask, signal);
  }
  sa.sa_sigaction = OnSignal;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO;

  for (int i = 0; i < ABSL_ARRAYSIZE(kExceptionSignals); ++i) {
    sigaction(kExceptionSignals[i], &sa, &old_handlers[i]);
  }
}

// Sets the interface to call back when a handled signal occurs.
void SignalHandler::RegisterNotificationInterface(
    KryptonNotificationInterface* interface) {
  notification_ = interface;

  // Lazily install the signal handlers if a notification interface is set.
  // Don't bother installing them on null. That way, removing a notification
  // interface is always safe.
  if (notification_ != nullptr) {
    absl::call_once(install_once_, SignalHandler::Install);
  }
}

}  // namespace krypton
}  // namespace privacy
