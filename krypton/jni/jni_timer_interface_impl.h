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

#ifndef PRIVACY_NET_KRYPTON_JNI_JNI_TIMER_INTERFACE_IMPL_H_
#define PRIVACY_NET_KRYPTON_JNI_JNI_TIMER_INTERFACE_IMPL_H_

#include <jni.h>

#include <memory>

#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/pal/timer_interface.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace jni {

class JniTimerInterfaceImpl : public TimerInterface {
 public:
  explicit JniTimerInterfaceImpl(jobject timer_id_manager_instance)
      : timer_id_manager_instance_(
            std::make_unique<JavaObject>(timer_id_manager_instance)) {}

  // Starts a timer for the given duration.
  absl::Status StartTimer(int timer_id, absl::Duration duration) override;

  // Cancels a running timer.
  void CancelTimer(int timer_id) override;

  // Cancel all timers
  void CancelAllTimers();

 private:
  std::unique_ptr<JavaObject> timer_id_manager_instance_;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_JNI_TIMER_INTERFACE_IMPL_H_
