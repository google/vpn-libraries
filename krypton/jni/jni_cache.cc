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

#include "privacy/net/krypton/jni/jni_cache.h"

#include <jni.h>
#include <jni_md.h>

#include <memory>
#include <optional>
#include <string>

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
constexpr char kHttpFetcherClass[] =
    "com/google/android/libraries/privacy/ppn/internal/http/HttpFetcher";
constexpr char kHttpFetcherPostJsonMethod[] = "postJson";
constexpr char kHttpFetcherPostJsonMethodSignature[] = "([B)[B";
constexpr char kHttpFetcherLookupDnsMethod[] = "lookupDns";
constexpr char kHttpFetcherLookupDnsMethodSignature[] =
    "(Ljava/lang/String;)Ljava/lang/String;";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/internal/http/HttpFetcher.java)

// com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider
// LINT.IfChange
constexpr char kOAuthTokenProviderInterface[] =
    "com/google/android/libraries/privacy/ppn/krypton/OAuthTokenProvider";
constexpr char kOAuthTokenProviderGetOAuthTokenMethod[] = "getOAuthToken";
constexpr char kOAuthTokenProviderGetOAuthTokenMethodSignature[] =
    "()Ljava/lang/String;";
constexpr char kOAuthTokenProviderGetAttestationDataMethod[] =
    "getAttestationData";
constexpr char kOAuthTokenProviderGetAttestationDataMethodSignature[] =
    "(Ljava/lang/String;)[B";
constexpr char kOAuthTokenProviderClearOAuthTokenMethod[] = "clearOAuthToken";
constexpr char kOAuthTokenProviderClearOAuthTokenMethodSignature[] =
    "(Ljava/lang/String;)V";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/OAuthTokenProvider.java)

// com.google.android.libraries.privacy.ppn.krypton.TimerIdManager
// LINT.IfChange
constexpr char kTimerIdManagerClass[] =
    "com/google/android/libraries/privacy/ppn/krypton/TimerIdManager";
constexpr char kTimerIdManagerStartTimerMethod[] = "startTimer";
constexpr char kTimerIdManagerStartTimerMethodSignature[] = "(II)Z";
constexpr char kTimerIdManagerCancelTimerMethod[] = "cancelTimer";
constexpr char kTimerIdManagerCancelTimerMethodSignature[] = "(I)Z";
// LINT.ThenChange(
// //depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/TimerIdManager.java)

// com.google.android.libraries.privacy.ppn.krypton.Krypton
// LINT.IfChange
constexpr char kKryptonClass[] =
    "com/google/android/libraries/privacy/ppn/krypton/KryptonImpl";
constexpr char kKryptonGetHttpFetcherMethod[] = "getHttpFetcher";
constexpr char kKryptonGetHttpFetcherMethodSignature[] =
    "()Lcom/google/android/libraries/privacy/ppn/internal/http/HttpFetcher;";
constexpr char kKryptonGetOAuthTokenProviderMethod[] = "getOAuthTokenProvider";
constexpr char kKryptonGetOAuthTokenProviderMethodSignature[] =
    "()Lcom/google/android/libraries/privacy/ppn/krypton/OAuthTokenProvider;";
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
constexpr char kKryptonCreateTcpFdMethod[] = "createTcpFd";
constexpr char kKryptonCreateTcpFdMethodSignature[] = "([B)I";

constexpr char kKryptonConfigureIpSecMethod[] = "configureIpSec";
constexpr char kKryptonConfigureIpSecMethodSignature[] = "([B)Z";

constexpr char kKryptonSnoozedMethod[] = "onKryptonSnoozed";
constexpr char kKryptonSnoozedMethodSignature[] = "([B)V";
constexpr char kKryptonResumedMethod[] = "onKryptonResumed";
constexpr char kKryptonResumedMethodSignature[] = "([B)V";
// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/KryptonImpl.java)

// LINT.IfChange
constexpr char kProvisionClass[] =
    "com/google/android/libraries/privacy/ppn/neon/Provision";
constexpr char kProvisionOnProvisionedMethod[] = "onProvisioned";
constexpr char kProvisionOnProvisionedMethodSignature[] = "(J[B)V";
constexpr char kProvisionOnProvisioningFailureMethod[] =
    "onProvisioningFailure";
constexpr char kProvisionOnProvisioningFailureSignature[] =
    "(JILjava/lang/String;[BZ)V";

// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/neon/Provision.java)

absl::StatusOr<jmethodID> GetMethod(JNIEnv* env, jclass klass,
                                    const char* method, const char* signature) {
  jmethodID m = env->GetMethodID(klass, method, signature);
  if (m == nullptr) {
    return absl::NotFoundError(
        absl::StrCat("unable to find method: ", method, signature));
  }
  return m;
}

absl::StatusOr<jclass> FindClass(JNIEnv* env, const char* path) {
  jclass c = env->FindClass(path);
  if (c == nullptr) {
    return absl::NotFoundError(absl::StrCat("unable to find class: ", path));
  }
  return c;
}

}  // namespace

std::optional<JNIEnv*> JniCache::GetJavaEnv() {
  JNIEnv* env = nullptr;
  jint env_res =
      java_vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  if (env_res == JNI_EDETACHED) {
    LOG(INFO) << "Attaching to new thread for JNI";
    auto res =
        java_vm_->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
    if (JNI_OK != res) {
      LOG(ERROR) << "Failed to AttachCurrentThread: ErrorCode " << res;
      return std::nullopt;
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
    return std::nullopt;
  } else if (env_res != JNI_OK) {
    LOG(ERROR) << "GetEnv: failed with unknown error " << env_res;
    return std::nullopt;
  }
  // we do nothing if it is JNI_OK.
  return env;
}

void JniCache::Init(JNIEnv* env) { Init(env, false); }

void JniCache::Init(JNIEnv* env, bool include_neon) {
  // Never store the environment object as it's only applicable for this call.
  // Fetch the VM and store the krypton java object
  if (env->GetJavaVM(&java_vm_) != JNI_OK) {
    LOG(ERROR) << "Cannot fetch Java VM; exiting Krypton Native";
    JniCache::ThrowKryptonException("Failed to find Java VM");
    return;
  }

  auto status = InitializeCachedMembers(env, include_neon);
  if (!status.ok()) {
    LOG(ERROR) << status;
    ThrowKryptonException(status.ToString());
  }
}

absl::Status JniCache::InitializeCachedMembers(JNIEnv* env, bool include_neon) {
  PPN_ASSIGN_OR_RETURN(auto krypton_class, FindClass(env, kKryptonClass));

  PPN_RETURN_IF_ERROR(InitializeExceptions(env));
  PPN_RETURN_IF_ERROR(InitializeHttpFetcherMethods(env, krypton_class));
  PPN_RETURN_IF_ERROR(InitializeOAuthTokenProviderMethods(env, krypton_class));
  PPN_RETURN_IF_ERROR(InitializeTimerIdManager(env, krypton_class));
  PPN_RETURN_IF_ERROR(InitializeNotifications(env, krypton_class));
  PPN_RETURN_IF_ERROR(InitializeVpnServiceMethods(env, krypton_class));
  if (include_neon) {
    PPN_RETURN_IF_ERROR(InitializeProvision(env));
  }

  return absl::OkStatus();
}

absl::Status JniCache::InitializeHttpFetcherMethods(JNIEnv* env,
                                                    jclass krypton_class) {
  LOG(INFO) << "Initializing HttpFetcher methods";

  PPN_ASSIGN_OR_RETURN(auto http_fetcher_class,
                       FindClass(env, kHttpFetcherClass));

  PPN_ASSIGN_OR_RETURN(
      krypton_get_http_fetcher_method_,
      GetMethod(env, krypton_class, kKryptonGetHttpFetcherMethod,
                kKryptonGetHttpFetcherMethodSignature));

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

absl::Status JniCache::InitializeOAuthTokenProviderMethods(
    JNIEnv* env, jclass krypton_class) {
  LOG(INFO) << "Initializing OAuthTokenProvider methods";

  PPN_ASSIGN_OR_RETURN(auto oauth_token_provider_interface,
                       FindClass(env, kOAuthTokenProviderInterface));

  PPN_ASSIGN_OR_RETURN(
      krypton_get_oauth_token_provider_method_,
      GetMethod(env, krypton_class, kKryptonGetOAuthTokenProviderMethod,
                kKryptonGetOAuthTokenProviderMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      oauth_token_provider_get_oauth_token_method_,
      GetMethod(env, oauth_token_provider_interface,
                kOAuthTokenProviderGetOAuthTokenMethod,
                kOAuthTokenProviderGetOAuthTokenMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      oauth_token_provider_get_attestation_data_method_,
      GetMethod(env, oauth_token_provider_interface,
                kOAuthTokenProviderGetAttestationDataMethod,
                kOAuthTokenProviderGetAttestationDataMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      oauth_token_provider_clear_oauth_token_method_,
      GetMethod(env, oauth_token_provider_interface,
                kOAuthTokenProviderClearOAuthTokenMethod,
                kOAuthTokenProviderClearOAuthTokenMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeTimerIdManager(JNIEnv* env,
                                                jclass krypton_class) {
  LOG(INFO) << "Initializing the TimerIdManager method";

  PPN_ASSIGN_OR_RETURN(auto timer_id_manager_class,
                       FindClass(env, kTimerIdManagerClass));

  PPN_ASSIGN_OR_RETURN(
      krypton_get_timer_id_manager_method_,
      GetMethod(env, krypton_class, kKryptonGetTimerIdManagerMethod,
                kKryptonGetTimerIdManagerMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      timer_id_manager_start_timer_method_,
      GetMethod(env, timer_id_manager_class, kTimerIdManagerStartTimerMethod,
                kTimerIdManagerStartTimerMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      timer_id_manager_cancel_timer_method_,
      GetMethod(env, timer_id_manager_class, kTimerIdManagerCancelTimerMethod,
                kTimerIdManagerCancelTimerMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeExceptions(JNIEnv* env) {
  LOG(INFO) << "Initializing Exceptions";
  PPN_ASSIGN_OR_RETURN(auto exception_class,
                       FindClass(env, kKryptonExceptionClass));
  krypton_exception_class_ = std::make_unique<JavaClass>(exception_class);
  return absl::OkStatus();
}

absl::Status JniCache::InitializeNotifications(JNIEnv* env,
                                               jclass krypton_class) {
  LOG(INFO) << "Initializing Notifications";

  PPN_ASSIGN_OR_RETURN(krypton_connected_method_,
                       GetMethod(env, krypton_class, kKryptonConnectedMethod,
                                 kKryptonConnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_connecting_method_,
                       GetMethod(env, krypton_class, kKryptonConnectingMethod,
                                 kKryptonConnectingMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_control_plane_connected_method_,
      GetMethod(env, krypton_class, kKryptonControlPlaneConnectedMethod,
                kKryptonControlPlaneConnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_status_updated_method_,
      GetMethod(env, krypton_class, kKryptonStatusUpdatedMethod,
                kKryptonStatusUpdatedMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_disconnected_method_,
                       GetMethod(env, krypton_class, kKryptonDisconnectedMethod,
                                 kKryptonDisconnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_network_disconnected_method_,
      GetMethod(env, krypton_class, kKryptonNetworkDisconnectedMethod,
                kKryptonNetworkDisconnectedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_permanent_failure_method_,
      GetMethod(env, krypton_class, kKryptonPermanentFailureMethod,
                kKryptonPermanentFailureMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_crashed_method_,
                       GetMethod(env, krypton_class, kKryptonCrashedMethod,
                                 kKryptonCrashedMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_waiting_to_reconnect_method_,
      GetMethod(env, krypton_class, kKryptonWaitingToReconnectMethod,
                kKryptonWaitingToReconnectMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_snoozed_method_,
                       GetMethod(env, krypton_class, kKryptonSnoozedMethod,
                                 kKryptonSnoozedMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_resumed_method_,
                       GetMethod(env, krypton_class, kKryptonResumedMethod,
                                 kKryptonResumedMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeVpnServiceMethods(JNIEnv* env,
                                                   jclass krypton_class) {
  LOG(INFO) << "Initializing VpnService methods";

  PPN_ASSIGN_OR_RETURN(krypton_create_tun_fd_method_,
                       GetMethod(env, krypton_class, kKryptonCreateTunFdMethod,
                                 kKryptonCreateTunFdMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_create_network_fd_method_,
      GetMethod(env, krypton_class, kKryptonCreateNetworkFdMethod,
                kKryptonCreateNetworkFdMethodSignature));

  PPN_ASSIGN_OR_RETURN(krypton_create_tcp_fd_method_,
                       GetMethod(env, krypton_class, kKryptonCreateTcpFdMethod,
                                 kKryptonCreateTcpFdMethodSignature));

  PPN_ASSIGN_OR_RETURN(
      krypton_configure_ipsec_method_,
      GetMethod(env, krypton_class, kKryptonConfigureIpSecMethod,
                kKryptonConfigureIpSecMethodSignature));

  return absl::OkStatus();
}

absl::Status JniCache::InitializeProvision(JNIEnv* env) {
  LOG(INFO) << "Initializing Provision methods";

  PPN_ASSIGN_OR_RETURN(auto provision_class, FindClass(env, kProvisionClass));

  PPN_ASSIGN_OR_RETURN(
      provision_on_provisioned_method_,
      GetMethod(env, provision_class, kProvisionOnProvisionedMethod,
                kProvisionOnProvisionedMethodSignature));
  PPN_ASSIGN_OR_RETURN(
      provision_on_provisioning_failure_method_,
      GetMethod(env, provision_class, kProvisionOnProvisioningFailureMethod,
                kProvisionOnProvisioningFailureSignature));

  return absl::OkStatus();
}

jclass JniCache::GetKryptonExceptionClass() const {
  return krypton_exception_class_->get();
}

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
