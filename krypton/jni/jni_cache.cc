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
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

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

// com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher
// LINT.IfChange
constexpr char kHttpFetcherPostJsonMethod[] = "postJson";
constexpr char kHttpFetcherPostJsonMethodSignature[] = "([B)[B";
constexpr char kHttpFetcherLookupDnsMethod[] = "lookupDns";
constexpr char kHttpFetcherLookupDnsMethodSignature[] =
    "(Ljava/lang/String;)Ljava/lang/String;";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/internal/http/HttpFetcher.java)

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
    "()Lcom/google/android/libraries/privacy/ppn/internal/http/HttpFetcher;";
constexpr char kKryptonGetTimerIdManagerMethod[] = "getTimerIdManager";
constexpr char kKryptonGetTimerIdManagerMethodSignature[] =
    "()Lcom/google/android/libraries/privacy/ppn/krypton/TimerIdManager;";

// Notification methods.
constexpr char kKryptonConnectedMethod[] = "onConnected";
constexpr char kKryptonConnectedMethodSignature[] = "([B)V";
constexpr char kKryptonConnectingMethod[] = "onConnecting";
constexpr char kKryptonConnectingMethodSignature[] = "([B)V";
constexpr char kKryptonControlPlaneConnectedMethod[] =
    "onControlPlaneConnected";
constexpr char kKryptonControlPlaneConnectedMethodSignature[] = "()V";
constexpr char kKryptonStatusUpdatedMethod[] = "onStatusUpdated";
constexpr char kKryptonStatusUpdatedMethodSignature[] = "([B)V";
constexpr char kKryptonDisconnectedMethod[] = "onDisconnected";
constexpr char kKryptonDisconnectedMethodSignature[] = "([B)V";
constexpr char kKryptonPermanentFailureMethod[] = "onPermanentFailure";
constexpr char kKryptonPermanentFailureMethodSignature[] =
    "(ILjava/lang/String;[B)V";
constexpr char kKryptonCrashedMethod[] = "onCrashed";
constexpr char kKryptonCrashedMethodSignature[] = "()V";
constexpr char kKryptonNetworkDisconnectedMethod[] = "onNetworkFailed";
constexpr char kKryptonNetworkDisconnectedMethodSignature[] =
    "([BILjava/lang/String;[B)V";
constexpr char kKryptonWaitingToReconnectMethod[] = "onWaitingToReconnect";
constexpr char kKryptonWaitingToReconnectMethodSignature[] = "([B)V";
constexpr char kKryptonCreateTunFdMethod[] = "createTunFd";
constexpr char kKryptonCreateTunFdMethodSignature[] = "([B)I";

constexpr char kKryptonCreateNetworkFdMethod[] = "createNetworkFd";
constexpr char kKryptonCreateNetworkFdMethodSignature[] = "([B)I";
constexpr char kKryptonGetOAuthTokenMethod[] = "getOAuthToken";
constexpr char kKryptonGetOAuthTokenMethodSignature[] = "()Ljava/lang/String;";
constexpr char kKryptonConfigureIpSecMethod[] = "configureIpSec";
constexpr char kKryptonConfigureIpSecMethodSignature[] = "([B)Z";

constexpr char kKryptonSnoozedMethod[] = "onKryptonSnoozed";
constexpr char kKryptonSnoozedMethodSignature[] = "([B)V";
constexpr char kKryptonResumedMethod[] = "onKryptonResumed";
constexpr char kKryptonResumedMethodSignature[] = "([B)V";
// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/KryptonImpl.java)

absl::StatusOr<jmethodID> GetMethod(JNIEnv* env, jclass klass,
                                    const char* method, const char* signature) {
  jmethodID m = env->GetMethodID(klass, method, signature);
  if (m == nullptr) {
    return absl::NotFoundError(
        absl::StrCat("unable to find method: ", method, signature));
  }
  return m;
}

absl::StatusOr<jclass> GetObjectClass(JNIEnv* env, jobject obj) {
  jclass c = env->GetObjectClass(obj);
  if (c == nullptr) {
    return absl::NotFoundError("unable to get object class");
  }
  return c;
}

absl::StatusOr<jclass> FindClass(JNIEnv* env, const char* path) {
  jclass c = env->FindClass(path);
  if (c == nullptr) {
    return absl::NotFoundError(absl::StrCat("unable to find class: ", path));
  }
  return c;
}

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

  krypton_object_ =
      std::make_unique<JavaObject<jobject>>(env, krypton_instance);

  auto status = InitializeCachedMembers(env);
  if (!status.ok()) {
    LOG(ERROR) << status;
    ThrowKryptonException(status.ToString());
  }
}

absl::Status JniCache::InitializeCachedMembers(JNIEnv* env) {
  PPN_ASSIGN_OR_RETURN(jclass krypton_class,
                       GetObjectClass(env, GetKryptonObject()));
  krypton_class_ = std::make_unique<JavaObject<jclass>>(env, krypton_class);

  PPN_RETURN_IF_ERROR(InitializeLogMethod(env));
  PPN_RETURN_IF_ERROR(InitializeExceptions(env));
  PPN_RETURN_IF_ERROR(InitializeHttpFetcherMethod(env));
  PPN_RETURN_IF_ERROR(InitializeTimerIdManager(env));
  PPN_RETURN_IF_ERROR(InitializeNotifications(env));
  PPN_RETURN_IF_ERROR(InitializeVpnServiceMethods(env));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeHttpFetcherMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing the HttpFetcher method";

  // Step 1: Get HttpFetcher object in Krypton object.
  PPN_ASSIGN_OR_RETURN(
      jmethodID get_http_fetcher_method,
      GetMethod(env, GetKryptonClass(), kKryptonGetHttpFetcherMethod,
                kKryptonGetHttpFetcherMethodSignature));

  jobject http_fetcher_object = static_cast<jobject>(
      env->CallObjectMethod(GetKryptonObject(), get_http_fetcher_method));
  if (http_fetcher_object == nullptr) {
    return absl::InternalError("failed to retrieve HttpFetcher");
  }
  http_fetcher_object_ =
      std::make_unique<JavaObject<jobject>>(env, http_fetcher_object);

  PPN_ASSIGN_OR_RETURN(jclass http_fetcher_class,
                       GetObjectClass(env, http_fetcher_object));
  http_fetcher_class_ =
      std::make_unique<JavaObject<jclass>>(env, http_fetcher_class);

  // Step 2: Save the Method Ids.
  PPN_ASSIGN_OR_RETURN(
      http_fetcher_post_json_method_,
      GetMethod(env, http_fetcher_class, kHttpFetcherPostJsonMethod,
                kHttpFetcherPostJsonMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      http_fetcher_lookup_dns_method_,
      GetMethod(env, http_fetcher_class, kHttpFetcherLookupDnsMethod,
                kHttpFetcherLookupDnsMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeTimerIdManager(JNIEnv* env) {
  LOG(INFO) << "Initializing the TimerIdManager method";

  // Step 1: Get TimerIdManager object in Krypton object.
  PPN_ASSIGN_OR_RETURN(
      jmethodID get_timer_id_manager_method,
      GetMethod(env, GetKryptonClass(), kKryptonGetTimerIdManagerMethod,
                kKryptonGetTimerIdManagerMethodSignature));

  jobject timer_id_manager_object = static_cast<jobject>(
      env->CallObjectMethod(GetKryptonObject(), get_timer_id_manager_method));
  if (timer_id_manager_object == nullptr) {
    return absl::InternalError("failed to retrieve TimerIdManager");
  }
  timer_id_manager_object_ =
      std::make_unique<JavaObject<jobject>>(env, timer_id_manager_object);

  PPN_ASSIGN_OR_RETURN(jclass timer_id_manager_class,
                       GetObjectClass(env, timer_id_manager_object));
  timer_id_manager_class_ =
      std::make_unique<JavaObject<jclass>>(env, timer_id_manager_class);

  // Step 2: Save the Method Ids.
  PPN_ASSIGN_OR_RETURN(
      timer_id_manager_start_timer_method_,
      GetMethod(env, timer_id_manager_class, kTimerIdManagerStartTimerMethod,
                kTimerIdManagerStartTimerMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      timer_id_manager_cancel_timer_method_,
      GetMethod(env, timer_id_manager_class, kTimerIdManagerCancelTimerMethod,
                kTimerIdManagerCancelTimerMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      timer_id_manager_cancel_all_timers_method_,
      GetMethod(env, timer_id_manager_class,
                kTimerIdManagerCancelAllTimersMethod,
                kTimerIdManagerCancelAllTimersMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeExceptions(JNIEnv* env) {
  LOG(INFO) << "Initializing Exceptions";
  PPN_ASSIGN_OR_RETURN(auto exception_class,
                       FindClass(env, kKryptonExceptionClass));
  krypton_exception_class_ =
      std::make_unique<JavaObject<jclass>>(env, exception_class);
  return absl::OkStatus();
}

absl::Status JniCache::InitializeNotifications(JNIEnv* env) {
  LOG(INFO) << "Initializing Notifications";

  PPN_ASSIGN_OR_RETURN(
      krypton_connected_method_,
      GetMethod(env, GetKryptonClass(), kKryptonConnectedMethod,
                kKryptonConnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_connecting_method_,
      GetMethod(env, GetKryptonClass(), kKryptonConnectingMethod,
                kKryptonConnectingMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_control_plane_connected_method_,
      GetMethod(env, GetKryptonClass(), kKryptonControlPlaneConnectedMethod,
                kKryptonControlPlaneConnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_status_updated_method_,
      GetMethod(env, GetKryptonClass(), kKryptonStatusUpdatedMethod,
                kKryptonStatusUpdatedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_disconnected_method_,
      GetMethod(env, GetKryptonClass(), kKryptonDisconnectedMethod,
                kKryptonDisconnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_network_disconnected_method_,
      GetMethod(env, GetKryptonClass(), kKryptonNetworkDisconnectedMethod,
                kKryptonNetworkDisconnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_permanent_failure_method_,
      GetMethod(env, GetKryptonClass(), kKryptonPermanentFailureMethod,
                kKryptonPermanentFailureMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_crashed_method_,
                       GetMethod(env, GetKryptonClass(), kKryptonCrashedMethod,
                                 kKryptonCrashedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_waiting_to_reconnect_method_,
      GetMethod(env, GetKryptonClass(), kKryptonWaitingToReconnectMethod,
                kKryptonWaitingToReconnectMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_snoozed_method_,
                       GetMethod(env, GetKryptonClass(), kKryptonSnoozedMethod,
                                 kKryptonSnoozedMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_resumed_method_,
                       GetMethod(env, GetKryptonClass(), kKryptonResumedMethod,
                                 kKryptonResumedMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeLogMethod(JNIEnv* env) {
  LOG(INFO) << "Initializing Log method";
  krypton_log_method_ = env->GetStaticMethodID(
      GetKryptonClass(), kKryptonLogMethod, kKryptonLogMethodSignature);
  if (krypton_log_method_ == nullptr) {
    return absl::NotFoundError("unable to find log method");
  }
  return absl::OkStatus();
}

absl::Status JniCache::InitializeVpnServiceMethods(JNIEnv* env) {
  LOG(INFO) << "Initializing VpnService methods";

  PPN_ASSIGN_OR_RETURN(
      krypton_create_tun_fd_method_,
      GetMethod(env, GetKryptonClass(), kKryptonCreateTunFdMethod,
                kKryptonCreateTunFdMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_create_network_fd_method_,
      GetMethod(env, GetKryptonClass(), kKryptonCreateNetworkFdMethod,
                kKryptonCreateNetworkFdMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_get_oauth_token_method_,
      GetMethod(env, GetKryptonClass(), kKryptonGetOAuthTokenMethod,
                kKryptonGetOAuthTokenMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_configure_ipsec_method_,
      GetMethod(env, GetKryptonClass(), kKryptonConfigureIpSecMethod,
                kKryptonConfigureIpSecMethodSignature));

  return absl::OkStatus();
}

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
