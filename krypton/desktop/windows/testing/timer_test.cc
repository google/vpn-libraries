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

#include <memory>

#include "base/init_google.h"
#include "base/logging.h"
#include "privacy/net/krypton/timer_manager.h"

using privacy::krypton::windows::Timer;

bool process_message = true;

void RegisteredCallback() {
  LOG(INFO) << "Hello from RegisteredCallback";
  process_message = false;
}

// This function MUST be called to get the timers running if you don't have
// a WindowsProc that handles this timer, that is, if you passed NULL in the
// first parameter of SetTimer
void ProcessTimerMessages() {
  HWND hwndTimer = nullptr;  // handle to window for timer messages
  MSG msg;                   // message structure

  while (process_message &&
         GetMessage(&msg,     // message structure
                    nullptr,  // handle to window to receive the message
                    NULL,     // lowest message to examine
                    NULL)     // highest message to examine
             != 0 &&
         GetMessage(&msg, nullptr, NULL, NULL) != -1) {
    // Post WM_TIMER messages to the hwndTimer procedure.

    if (msg.message == WM_TIMER) {
      msg.hwnd = hwndTimer;
    }

    TranslateMessage(&msg);  // translates virtual-key codes
    DispatchMessage(&msg);   // dispatches message to window
    absl::SleepFor(absl::Seconds(1));
  }
}

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  auto timer_manager =
      std::make_unique<privacy::krypton::TimerManager>(Timer::Get());

  auto timer_status =
      timer_manager->StartTimer(absl::Seconds(10), RegisteredCallback);

  timer_status =
      timer_manager->StartTimer(absl::Seconds(5), RegisteredCallback);

  timer_manager->CancelTimer(1);

  ProcessTimerMessages();

  return 0;
}
