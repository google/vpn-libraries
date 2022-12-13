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

#include <memory>
#include <string>

#include "base/init_google.h"
#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/http_fetcher.h"
#include "privacy/net/krypton/desktop/windows/timer.h"
#include "privacy/net/krypton/pal/timer_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/jsoncpp/writer.h"

using privacy::krypton::windows::HttpFetcher;
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
  HWND hwndTimer = NULL;  // handle to window for timer messages
  MSG msg;                // message structure

  while (process_message &&
         GetMessage(&msg,  // message structure
                    NULL,  // handle to window to receive the message
                    NULL,  // lowest message to examine
                    NULL)  // highest message to examine
             != 0 &&
         GetMessage(&msg, NULL, NULL, NULL) != -1) {
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

  auto http_fetcher = std::make_unique<HttpFetcher>();

  auto resolved_address = http_fetcher->LookupDns("na.b.g-tun.com");
  if (!resolved_address.ok()) {
    LOG(ERROR) << "LookupDns failed: " << resolved_address.status();
    return 0;
  }
  LOG(INFO) << "Result of LookupDns: " << resolved_address.value();

  // PublicKey Request
  auto url = "https://staging.zinc.cloud.cupronickel.goog/publickey";

  privacy::krypton::HttpRequest request;
  Json::Value json_body;
  json_body["get_public_key"] = true;

  Json::FastWriter writer;
  request.set_json_body(writer.write(json_body));
  request.set_url(url);

  auto http_response = http_fetcher->PostJson(request);
  LOG(INFO) << "Result of PostJson:";
  LOG(INFO) << "Status code: " << http_response.status().code();
  LOG(INFO) << "Status message: " << http_response.status().message();
  LOG(INFO) << "Json response: " << http_response.json_body();

  return 0;
}
