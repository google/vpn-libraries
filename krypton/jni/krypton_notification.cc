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

#include "privacy/net/krypton/jni/krypton_notification.h"

#include <jni.h>

#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/proto/connection_status.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace jni {

void KryptonNotification::Connected() {
  LOG(INFO) << "Sending Connected notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Connected notification";
    return;
  }

  // TODO: Pass a ConnectionStatus into this method.
  ConnectionStatus status;
  std::string statusBytes;
  status.SerializeToString(&statusBytes);

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->GetKryptonConnectedMethod(),
                              JavaByteArray(env.value(), statusBytes).get());
}

void KryptonNotification::Connecting() {
  LOG(INFO) << "Sending Connecting notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Connecting notification";
    return;
  }

  ConnectionStatus status;
  std::string statusBytes;
  status.SerializeToString(&statusBytes);

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->GetKryptonConnectingMethod(),
                              JavaByteArray(env.value(), statusBytes).get());
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

  ConnectionStatus status;
  std::string statusBytes;
  status.SerializeToString(&statusBytes);

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->
                              GetKryptonControlPlaneConnectedMethod(),
                              JavaByteArray(env.value(), statusBytes).get());
}

void KryptonNotification::StatusUpdated() {
  LOG(INFO) << "Sending StatusUpdated notification";
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send StatusUpdated notification";
    return;
  }

  // TODO: Pass a ConnectionStatus into this method.
  ConnectionStatus status;
  std::string status_bytes;
  status.SerializeToString(&status_bytes);

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->GetKryptonStatusUpdatedMethod(),
                              JavaByteArray(env.value(), status_bytes).get());
}

void KryptonNotification::Disconnected(const absl::Status& status) {
  LOG(INFO) << "Sending Disconnected notification with code "
            << status.raw_code() << ": " << status;
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send Disconnected notification";
    return;
  }

  env.value()->CallVoidMethod(
      jni_cache->GetKryptonObject(), jni_cache->GetKryptonDisconnectedMethod(),
      status.raw_code(),
      JavaString(env.value(), std::string(status.message())).get());
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

  env.value()->CallVoidMethod(
      jni_cache->GetKryptonObject(),
      jni_cache->GetKryptonPermanentFailureMethod(), status.raw_code(),
      JavaString(env.value(), std::string(status.message())).get());
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

  env.value()->CallVoidMethod(
      jni_cache->GetKryptonObject(),
      jni_cache->GetKryptonNetworkDisconnectedMethod(),
      JavaByteArray(env.value(), network_info_bytes).get(), status.raw_code(),
      JavaString(env.value(), std::string(status.message())).get());
}

void KryptonNotification::Crashed() {
  LOG(INFO) << "Sending Crashed notification";

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request TUN fd";
    return;
  }

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->GetKryptonCrashedMethod());
}

void KryptonNotification::WaitingToReconnect(const int64 retry_millis) {
  LOG(INFO) << "Sending WaitingToReconnect notification: " << retry_millis;
  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to send WaitingToReconnect notification";
    return;
  }

  env.value()->CallVoidMethod(jni_cache->GetKryptonObject(),
                              jni_cache->GetKryptonWaitingToReconnectMethod(),
                              retry_millis);
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
