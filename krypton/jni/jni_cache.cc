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

#include "privacy/net/krypton/jni/jni_cache.h"

#include <jni.h>
#include <jni_md.h>

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {
namespace jni {

namespace {
// Some notes for the JNI names
// Class: Class name should match the Java name. k<Class>Class e.g.
// kKryptonExceptionClass.
// Method: Method name should match the Java name. k<Class><Method>Method
// e.g. kKryptonGetHttpFetcherMethod.

// com.google.android.libraries.privacy.ppn.krypton.KryptonException
// LINT.IfChange
constexpr char kKryptonExceptionClass[] =
    "com/google/android/libraries/privacy/ppn/krypton/KryptonException";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/KryptonException.java)

// com.google.android.libraries.privacy.ppn.krypton.HttpFetcher
// LINT.IfChange
constexpr char kHttpFetcherPostJsonMethod[] = "postJson";
constexpr char kHttpFetcherPostJsonMethodSignature[] =
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/"
    "String;";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/HttpFetcher.java)

// com.google.android.libraries.privacy.ppn.krypton.TimerIdManager
// LINT.IfChange
constexpr char kTimerIdManagerStartTimerMethod[] = "startTimer";
constexpr char kTimerIdManagerStartTimerMethodSignature[] = "(II)Z";
constexpr char kTimerIdManagerCancelTimerMethod[] = "cancelTimer";
constexpr char kTimerIdManagerCancelTimerMethodSignature[] = "(I)Z";
constexpr char kTimerIdManagerCancelAllTimersMethod[] = "cancelAllTimers";
constexpr char kTimerIdManagerCancelAllTimersMethodSignature[] = "()V";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/TimerIdManager.java)

// com.google.android.libraries.privacy.ppn.krypton.Krypton
// LINT.IfChange
constexpr char kKryptonLogMethod[] = "log";
constexpr char kKryptonLogMethodSignature[] = "(Ljava/lang/String;)V";
constexpr char kKryptonGetHttpFetcherMethod[] = "getHttpFetcher";
constexpr char kKryptonGetHttpFetcherMethodSignature[] =
    "()Lcom/google/android/libraries/privacy/ppn/krypton/HttpFetcher;";
constexpr char kKryptonGetTimerIdManagerMethod[] = "getTimerIdManager";
constexpr char kKryptonGetTimerIdManagerMethodSignature[] =
    "()Lcom/google/android/libraries/privacy/ppn/krypton/TimerIdManager;";

// Notification methods.
constexpr char kKryptonConnectedMethod[] = "onConnected";
constexpr char kKryptonConnectedMethodSignature[] = "([B)V";
constexpr char kKryptonConnectingMethod[] = "onConnecting";
constexpr char kKryptonConnectingMethodSignature[] = "()V";
constexpr char kKryptonControlPlaneConnectedMethod[] =
    "onControlPlaneConnected";
constexpr char kKryptonControlPlaneConnectedMethodSignature[] = "()V";
constexpr char kKryptonStatusUpdatedMethod[] = "onStatusUpdated";
constexpr char kKryptonStatusUpdatedMethodSignature[] = "([B)V";
constexpr char kKryptonDisconnectedMethod[] = "onDisconnected";
constexpr char kKryptonDisconnectedMethodSignature[] = "(ILjava/lang/String;)V";
constexpr char kKryptonPermanentFailureMethod[] = "onPermanentFailure";
constexpr char kKryptonPermanentFailureMethodSignature[] =
    "(ILjava/lang/String;)V";
constexpr char kKryptonCrashedMethod[] = "onCrashed";
constexpr char kKryptonCrashedMethodSignature[] = "()V";
constexpr char kKryptonNetworkDisconnectedMethod[] = "onNetworkFailed";
constexpr char kKryptonNetworkDisconnectedMethodSignature[] =
    "([BILjava/lang/String;)V";
constexpr char kKryptonWaitingToReconnectMethod[] = "onWaitingToReconnect";
constexpr char kKryptonWaitingToReconnectMethodSignature[] = "(J)V";
constexpr char kKryptonCreateTunFdMethod[] = "createTunFd";
constexpr char kKryptonCreateTunFdMethodSignature[] = "([B)I";

constexpr char kKryptonCreateNetworkFdMethod[] = "createNetworkFd";
constexpr char kKryptonCreateNetworkFdMethodSignature[] = "([B)I";
constexpr char kKryptonGetOAuthTokenMethod[] = "getOAuthToken";
constexpr char kKryptonGetOAuthTokenMethodSignature[] = "()Ljava/lang/String;";
constexpr char kKryptonConfigureIpSecMethod[] = "configureIpSec";
constexpr char kKryptonConfigureIpSecMethodSignature[] = "([B)Z";
// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/KryptonImpl.java)
}  // namespace

absl::optional<JNIEnv*> JniCache::GetJavaEnv() {
  JNIEnv* env = nullptr;
  jint env_res =
      java_vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  if (env_res == JNI_EDETACHED) {
    LOG(INFO) << "Attaching to new thread for JNI";
    auto res =
        java_vm_->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
    if (JNI_OK != res) {
      LOG(ERROR) << "Failed to AttachCurrentThread: ErrorCode " << res;
      return absl::nullopt;
    }
    // Now that we've attached, we need to add a cleanup handler to the current
    // looper to detach when it's destroyed.
    auto* looper = utils::LooperThread::GetCurrentLooper();
    if (looper != nullptr) {
      JavaVM* jvm = java_vm_;
      looper->AddCleanupHandler([jvm] { jvm->DetachCurrentThread(); });
    } else {
      LOG(ERROR) << "JNI was attached from outside of a Looper.";
    }
  } else if (env_res == JNI_EVERSION) {
    LOG(ERROR) << "GetEnv: version not supported";
    return absl::nullopt;
  } else if (env_res != JNI_OK) {
    LOG(ERROR) << "GetEnv: failed with unknown error " << env_res;
    return absl::nullopt;
  }
  // we do nothing if it is JNI_OK.
  return env;
}

void JniCache::Init(JNIEnv* env, jobject krypton_instance) {
  // Never store the environment object as it's only applicable for this call.
  // Fetch the VM and store the krypton java object
  if (env->GetJavaVM(&java_vm_) != JNI_OK) {
    LOG(ERROR) << "Cannot fetch Java VM; exiting Krypton Native";
    JniCache::ThrowKryptonException("Failed to find Java VM");
    return;
  }
  // Java Krypton object and class that initiated the Init.
  krypton_object_ =
      std::make_unique<JavaObject<jobject>>(env, krypton_instance);
  jclass krypton_class = env->GetObjectClass(GetKryptonObject());
  krypton_class_ = std::make_unique<JavaObject<jclass>>(env, krypton_class);

  InitializeLogMethod(env);
  InitializeExceptions(env);
  InitializeHttpFetcherMethod(env);
  InitializeTimerIdManager(env);
  InitializeNotifications(env);
  InitializeCreateTunFdMethod(env);
  InitializeCreateNetworkFdMethod(env);
  InitializeGetOAuthTokenMethod(env);
  InitializeConfigureIpSecMethod(env);
}

void JniCache::InitializeHttpFetcherMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing the HttpFetcher method";

  // Step 1: Get HttpFetcher object in Krypton object.
  jmethodID get_http_fetcher_method =
      env->GetMethodID(GetKryptonClass(), kKryptonGetHttpFetcherMethod,
                       kKryptonGetHttpFetcherMethodSignature);

  if (get_http_fetcher_method == nullptr) {
    LOG(ERROR) << "Cannot retrieve the getHttpFetcher method";
    ThrowKryptonException("Cannot retrieve getHttpFetcher in Krypton.java");
    return;
  }
  jobject http_fetcher_object = static_cast<jobject>(
      env->CallObjectMethod(GetKryptonObject(), get_http_fetcher_method));
  if (http_fetcher_object == nullptr) {
    LOG(ERROR) << "Failed to retrieve HttpFetcher Object";
    ThrowKryptonException("Failed to retrieve HttpFetcher object");
    return;
  }
  http_fetcher_object_ =
      std::make_unique<JavaObject<jobject>>(env, http_fetcher_object);

  jclass http_fetcher_class = env->GetObjectClass(http_fetcher_object);
  if (http_fetcher_class == nullptr) {
    LOG(ERROR) << "Failed to find HttpFetcher class";
    ThrowKryptonException("Failed to find HttpFetcher class");
    return;
  }
  http_fetcher_class_ =
      std::make_unique<JavaObject<jclass>>(env, http_fetcher_class);

  // Step 2: Save the Method Id.
  http_fetcher_post_json_method_ =
      env->GetMethodID(http_fetcher_class, kHttpFetcherPostJsonMethod,
                       kHttpFetcherPostJsonMethodSignature);

  if (http_fetcher_post_json_method_ == nullptr) {
    LOG(ERROR) << "Failed to find postJson method";
    ThrowKryptonException("Failed to find postJson method");
    return;
  }
}

void JniCache::InitializeTimerIdManager(JNIEnv* env) {
  LOG(INFO) << "Initializing the TimerIdManager method";

  // Step 1: Get TimerIdManager object in Krypton object.
  jmethodID get_timer_id_manager_method =
      env->GetMethodID(GetKryptonClass(), kKryptonGetTimerIdManagerMethod,
                       kKryptonGetTimerIdManagerMethodSignature);

  if (get_timer_id_manager_method == nullptr) {
    LOG(ERROR) << "Cannot retrieve the getTimerIdManager method";
    ThrowKryptonException("Cannot retrieve getTimerIdManager in Krypton.java");
    return;
  }
  jobject timer_id_manager_object = static_cast<jobject>(
      env->CallObjectMethod(GetKryptonObject(), get_timer_id_manager_method));
  if (timer_id_manager_object == nullptr) {
    LOG(ERROR) << "Failed to retrieve TimerIdManager Object";
    ThrowKryptonException("Failed to retrieve TimerIdManager object");
    return;
  }
  timer_id_manager_object_ =
      std::make_unique<JavaObject<jobject>>(env, timer_id_manager_object);

  jclass timer_id_manager_class = env->GetObjectClass(timer_id_manager_object);
  if (timer_id_manager_class == nullptr) {
    LOG(ERROR) << "Failed to find TimerIdManager class";
    ThrowKryptonException("Failed to find TimerIdManager class");
    return;
  }
  timer_id_manager_class_ =
      std::make_unique<JavaObject<jclass>>(env, timer_id_manager_class);

  // Step 2: Save the Method Ids.
  // StartTimer
  timer_id_manager_start_timer_method_ =
      env->GetMethodID(timer_id_manager_class, kTimerIdManagerStartTimerMethod,
                       kTimerIdManagerStartTimerMethodSignature);

  if (timer_id_manager_start_timer_method_ == nullptr) {
    LOG(ERROR) << "Failed to find startTimer method";
    ThrowKryptonException("Failed to find startTimer method");
    return;
  }

  // CancelTimer
  timer_id_manager_cancel_timer_method_ =
      env->GetMethodID(timer_id_manager_class, kTimerIdManagerCancelTimerMethod,
                       kTimerIdManagerCancelTimerMethodSignature);

  if (timer_id_manager_cancel_timer_method_ == nullptr) {
    LOG(ERROR) << "Failed to find cancelTimer method";
    ThrowKryptonException("Failed to find cancelTimer method");
    return;
  }

  // CancelAllTimers
  timer_id_manager_cancel_all_timers_method_ = env->GetMethodID(
      timer_id_manager_class, kTimerIdManagerCancelAllTimersMethod,
      kTimerIdManagerCancelAllTimersMethodSignature);

  if (timer_id_manager_cancel_all_timers_method_ == nullptr) {
    LOG(ERROR) << "Failed to find cancelAllTimers method";
    ThrowKryptonException("Failed to find cancelAllTimers method");
    return;
  }
}

void JniCache::InitializeExceptions(JNIEnv* env) {
  LOG(INFO) << "Initializing Exceptions";
  auto exception_class = env->FindClass(kKryptonExceptionClass);
  if (exception_class == nullptr) {
    LOG(ERROR) << "Failed to find KryptonException class";
    return;
  }
  krypton_exception_class_ =
      std::make_unique<JavaObject<jclass>>(env, exception_class);
}

void JniCache::InitializeNotifications(JNIEnv* env) {
  LOG(INFO) << "Initializing Notifications";

  krypton_connected_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonConnectedMethod,
                       kKryptonConnectedMethodSignature);
  if (krypton_connected_method_ == nullptr) {
    ThrowKryptonException("Cannot find onConnected method in Krypton.java");
    return;
  }

  krypton_connecting_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonConnectingMethod,
                       kKryptonConnectingMethodSignature);
  if (krypton_connecting_method_ == nullptr) {
    ThrowKryptonException("Cannot find onConnecting method in Krypton.java");
    return;
  }

  krypton_control_plane_connected_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonControlPlaneConnectedMethod,
                       kKryptonControlPlaneConnectedMethodSignature);
  if (krypton_control_plane_connected_method_ == nullptr) {
    ThrowKryptonException(
        "Cannot find onControlPlaneConnected method in Krypton.java");
    return;
  }

  krypton_status_updated_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonStatusUpdatedMethod,
                       kKryptonStatusUpdatedMethodSignature);
  if (krypton_status_updated_method_ == nullptr) {
    ThrowKryptonException("Cannot find onStatusUpdated method in Krypton.java");
    return;
  }

  krypton_disconnected_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonDisconnectedMethod,
                       kKryptonDisconnectedMethodSignature);
  if (krypton_disconnected_method_ == nullptr) {
    ThrowKryptonException("Cannot find onDisconnected method in Krypton.java");
    return;
  }

  krypton_network_disconnected_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonNetworkDisconnectedMethod,
                       kKryptonNetworkDisconnectedMethodSignature);
  if (krypton_network_disconnected_method_ == nullptr) {
    ThrowKryptonException(
        "Cannot find onNetworkDisconnected method in Krypton.java");
    return;
  }

  krypton_permanent_failure_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonPermanentFailureMethod,
                       kKryptonPermanentFailureMethodSignature);
  if (krypton_permanent_failure_method_ == nullptr) {
    ThrowKryptonException(
        "Cannot find onPermanentFailure method in Krypton.java");
    return;
  }

  krypton_crashed_method_ = env->GetMethodID(
      GetKryptonClass(), kKryptonCrashedMethod, kKryptonCrashedMethodSignature);
  if (krypton_crashed_method_ == nullptr) {
    ThrowKryptonException("Cannot find onCrashed method in Krypton.java");
    return;
  }

  krypton_waiting_to_reconnect_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonWaitingToReconnectMethod,
                       kKryptonWaitingToReconnectMethodSignature);
  if (krypton_waiting_to_reconnect_method_ == nullptr) {
    ThrowKryptonException(
        "Cannot find onWaitingToReconnect method in Krypton.java");
    return;
  }
}

void JniCache::InitializeLogMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing Log method";

  krypton_log_method_ = env->GetStaticMethodID(
      GetKryptonClass(), kKryptonLogMethod, kKryptonLogMethodSignature);
  if (krypton_log_method_ == nullptr) {
    LOG(ERROR) << "Cannot find the log method";
  }
}

void JniCache::InitializeCreateTunFdMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing CreateTunFd method";

  krypton_create_tun_fd_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonCreateTunFdMethod,
                       kKryptonCreateTunFdMethodSignature);
  if (krypton_create_tun_fd_method_ == nullptr) {
    LOG(ERROR) << "Cannot find the createTunFd method";
  }
}

void JniCache::InitializeCreateNetworkFdMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing CreateNetworkFd method";

  krypton_create_network_fd_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonCreateNetworkFdMethod,
                       kKryptonCreateNetworkFdMethodSignature);
  if (krypton_create_network_fd_method_ == nullptr) {
    LOG(ERROR) << "Cannot find the createNetworkFd method";
  }
}

void JniCache::InitializeGetOAuthTokenMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing GetOAuthToken method";

  krypton_get_oauth_token_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonGetOAuthTokenMethod,
                       kKryptonGetOAuthTokenMethodSignature);
  if (krypton_get_oauth_token_method_ == nullptr) {
    LOG(ERROR) << "Cannot find the getOAuthToken method";
  }
}

void JniCache::InitializeConfigureIpSecMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing configureIpSec method";

  krypton_configure_ipsec_method_ =
      env->GetMethodID(GetKryptonClass(), kKryptonConfigureIpSecMethod,
                       kKryptonConfigureIpSecMethodSignature);
  if (krypton_configure_ipsec_method_ == nullptr) {
    LOG(ERROR) << "Cannot find configureIpSec method";
  }
}

JniCache::JniCache() {}

jclass JniCache::GetKryptonExceptionClass() const {
  return krypton_exception_class_->get();
}

jobject JniCache::GetHttpFetcherObject() const {
  return http_fetcher_object_->get();
}

jclass JniCache::GetHttpFetcherClass() const {
  return http_fetcher_class_->get();
}

jclass JniCache::GetTimerIdManagerClass() const {
  return timer_id_manager_class_->get();
}

jobject JniCache::GetTimerIdManagerObject() const {
  return timer_id_manager_object_->get();
}

jclass JniCache::GetKryptonClass() const { return krypton_class_->get(); }

jobject JniCache::GetKryptonObject() const { return krypton_object_->get(); }

void JniCache::ThrowKryptonException(const std::string& message) {
  // Log the error
  LOG(ERROR) << "Krypton Exception: " << message;
  auto env_opt = GetJavaEnv();
  if (!env_opt) {
    LOG(ERROR) << "Cannot throw KryptonException with message " << message;
    return;
  }
  // Clear any pending exceptions.
  auto* env = env_opt.value();
  env->ExceptionDescribe();
  env->ExceptionClear();
  env->ThrowNew(GetKryptonExceptionClass(), message.c_str());
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
