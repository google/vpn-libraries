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

#include "privacy/net/krypton/jni/jni_timer_interface_impl.h"

#include <jni.h>

#include <optional>

#include "base/logging.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace jni {

// Starts a timer for the given duration.
absl::Status JniTimerInterfaceImpl::StartTimer(int timer_id,
                                               absl::Duration duration) {
  LOG(INFO) << "Calling StartTimer JNI method for timer id " << timer_id
            << " with duration " << duration;

  auto jni_ppn = JniCache::Get();
  auto env = jni_ppn->GetJavaEnv();
  if (!env) {
    return absl::NotFoundError("Cannot find jni env");
  }

  auto result = static_cast<jboolean>(env.value()->CallBooleanMethod(
      timer_id_manager_instance_->get(),
      jni_ppn->GetTimerIdManagerStartTimerMethod(), timer_id,
      duration / absl::Milliseconds(1)));

  if (result == 0) {
    return absl::InternalError("Start timer failed");
  }
  return absl::OkStatus();
}

// Cancels a running timer.
void JniTimerInterfaceImpl::CancelTimer(int timer_id) {
  LOG(INFO) << "Calling CancelTimer JNI method for timer id " << timer_id;

  auto jni_ppn = JniCache::Get();
  auto env = jni_ppn->GetJavaEnv();
  if (!env) {
    return;
  }

  auto result = static_cast<jboolean>(env.value()->CallBooleanMethod(
      timer_id_manager_instance_->get(),
      jni_ppn->GetTimerIdManagerCancelTimerMethod(), timer_id));

  if (result == 0) {
    LOG(ERROR) << "Error cancelling timer with id" << timer_id;
    return;
  }
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
