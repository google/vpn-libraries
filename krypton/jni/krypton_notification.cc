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

#include "privacy/net/krypton/jni/krypton_notification.h"

#include <jni.h>

#include <cstdint>
#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/common/proto/ppn_status.proto.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace jni {

void KryptonNotification::Connected(const ConnectionStatus& status) {
  LOG(INFO) << "Sending Connected notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Connected notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonConnectedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::Connecting(const ConnectingStatus& status) {
  LOG(INFO) << "Sending Connecting notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Connecting notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonConnectingMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::ControlPlaneConnected() {
  LOG(INFO) << "Sending ControlPlaneConnected notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) <<
        "Cannot find JavaEnv to send ControlPlaneConnected notification";
    return;
  }

  env.value()->CallVoidMethod(
      krypton_instance_->get(),
      jni_cache->GetKryptonControlPlaneConnectedMethod());
}

void KryptonNotification::StatusUpdated(const ConnectionStatus& status) {
  LOG(INFO) << "Sending StatusUpdated notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send StatusUpdated notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonStatusUpdatedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::Disconnected(const DisconnectionStatus& status) {
  LOG(INFO) << "Sending Disconnected notification with code " << status.code()
            << ": " << status.message();
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Disconnected notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonDisconnectedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::PermanentFailure(const absl::Status& status) {
  LOG(INFO) << "Sending PermanentFailure notification with code "
            << status.raw_code() << ": " << status;
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send PermanentFailure notification";
    return;
  }

  ppn::PpnStatusDetails details = utils::GetPpnStatusDetails(status);
  std::string details_bytes;
  details.SerializeToString(&details_bytes);

  env.value()->CallVoidMethod(
      krypton_instance_->get(), jni_cache->GetKryptonPermanentFailureMethod(),
      status.raw_code(),
      JavaString(env.value(), std::string(status.message())).get(),
      JavaByteArray(env.value(), details_bytes).get());
}

void KryptonNotification::NetworkDisconnected(const NetworkInfo& network_info,
                                              const absl::Status& status) {
  LOG(INFO) << "Sending NetworkDisconnected with status " << status;

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request TUN fd";
    return;
  }

  std::string network_info_bytes;
  network_info.SerializeToString(&network_info_bytes);

  ppn::PpnStatusDetails details = utils::GetPpnStatusDetails(status);
  std::string details_bytes;
  details.SerializeToString(&details_bytes);

  env.value()->CallVoidMethod(
      krypton_instance_->get(),
      jni_cache->GetKryptonNetworkDisconnectedMethod(),
      JavaByteArray(env.value(), network_info_bytes).get(), status.raw_code(),
      JavaString(env.value(), std::string(status.message())).get(),
      JavaByteArray(env.value(), details_bytes).get());
}

void KryptonNotification::Crashed() {
  LOG(INFO) << "Sending Crashed notification";

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request TUN fd";
    return;
  }

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonCrashedMethod());
}

void KryptonNotification::WaitingToReconnect(const ReconnectionStatus& status) {
  LOG(INFO) << "Sending WaitingToReconnect notification.";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send WaitingToReconnect notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonWaitingToReconnectMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::Snoozed(const SnoozeStatus& status) {
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Snoozed notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonSnoozedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::Resumed(const ResumeStatus& status) {
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Resumed notification";
    return;
  }

  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(krypton_instance_->get(),
                              jni_cache->GetKryptonResumedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
