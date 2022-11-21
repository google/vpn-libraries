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

#ifndef PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_
#define PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_

#include <jni.h>

#include <memory>
#include <optional>
#include <string>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace jni {

template <typename T>
class JavaObjectBase;

using JavaClass = JavaObjectBase<jclass>;

// This class keeps the global references of the Java VM and necessary
// Java class contexts and methods that could be called from the C++.
// This is a singleton class and thread safe.
class JniCache {
 public:
  static JniCache* Get() {
    static JniCache* kInstance = new JniCache();
    return kInstance;
  }

  // Can be called multiple times and this will reinitialize the java methods.
  void Init(JNIEnv* env);
  void Init(JNIEnv* env, bool include_neon);

  // Current VM.
  JavaVM* GetJavaVm() const { return java_vm_; }

  // Retrieves the Java Environment to call the appropriate Java method.
  std::optional<JNIEnv*> GetJavaEnv();

  // Throws exception to the java layer when krypton API is called.
  void ThrowKryptonException(const std::string& message);

  // com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher
  jmethodID GetHttpFetcherPostJsonMethod() const {
    return http_fetcher_post_json_method_;
  }
  jmethodID GetHttpFetcherLookupDnsMethod() const {
    return http_fetcher_lookup_dns_method_;
  }

  // com.google.android.libraries.privacy.ppn.krypton.OAuthTokenProvider
  jmethodID GetOAuthTokenProviderGetOAuthTokenMethod() const {
    return oauth_token_provider_get_oauth_token_method_;
  }

  jmethodID GetOAuthTokenProviderGetAttestationDataMethod() const {
    return oauth_token_provider_get_attestation_data_method_;
  }

  // com.google.android.libraries.privacy.ppn.krypton.TimerIdManager
  jmethodID GetTimerIdManagerStartTimerMethod() const {
    return timer_id_manager_start_timer_method_;
  }
  jmethodID GetTimerIdManagerCancelTimerMethod() const {
    return timer_id_manager_cancel_timer_method_;
  }
  jmethodID GetTimerIdManagerCancelAllTimersMethod() const {
    return timer_id_manager_cancel_all_timers_method_;
  }

  // com.google.android.libraries.privacy.ppn.krypton.KryptonImpl.
  jmethodID GetKryptonGetHttpFetcherMethod() const {
    return krypton_get_http_fetcher_method_;
  }
  jmethodID GetKryptonGetOAuthTokenProviderMethod() const {
    return krypton_get_oauth_token_provider_method_;
  }
  jmethodID GetKryptonGetTimerIdManagerMethod() const {
    return krypton_get_timer_id_manager_method_;
  }

  // Notification methods.
  jmethodID GetKryptonConnectedMethod() const {
    return krypton_connected_method_;
  }
  jmethodID GetKryptonConnectingMethod() const {
    return krypton_connecting_method_;
  }
  jmethodID GetKryptonControlPlaneConnectedMethod() const {
    return krypton_control_plane_connected_method_;
  }
  jmethodID GetKryptonStatusUpdatedMethod() const {
    return krypton_status_updated_method_;
  }
  jmethodID GetKryptonDisconnectedMethod() const {
    return krypton_disconnected_method_;
  }
  jmethodID GetKryptonNetworkDisconnectedMethod() const {
    return krypton_network_disconnected_method_;
  }
  jmethodID GetKryptonPermanentFailureMethod() const {
    return krypton_permanent_failure_method_;
  }
  jmethodID GetKryptonCrashedMethod() const { return krypton_crashed_method_; }
  jmethodID GetKryptonWaitingToReconnectMethod() const {
    return krypton_waiting_to_reconnect_method_;
  }
  jmethodID GetKryptonSnoozedMethod() const { return krypton_snoozed_method_; }
  jmethodID GetKryptonResumedMethod() const { return krypton_resumed_method_; }

  jmethodID GetKryptonCreateTunFdMethod() const {
    return krypton_create_tun_fd_method_;
  }
  jmethodID GetKryptonCreateNetworkFdMethod() const {
    return krypton_create_network_fd_method_;
  }
  jmethodID GetKryptonCreateTcpFdMethod() const {
    return krypton_create_tcp_fd_method_;
  }
  jmethodID GetKryptonConfigureIpSecMethod() const {
    return krypton_configure_ipsec_method_;
  }

  // privacy.ppn.neon.Provision
  jmethodID GetProvisionOnProvisionedMethod() const {
    return provision_on_provisioned_method_;
  }
  jmethodID GetProvisionOnProvisioningFailureMethod() const {
    return provision_on_provisioning_failure_method_;
  }

 private:
  JniCache() {}
  ~JniCache() = default;

  // Initializes all of the cached data members.
  absl::Status InitializeCachedMembers(JNIEnv* env, bool include_neon);

  absl::Status InitializeHttpFetcherMethods(JNIEnv* env, jclass krypton_class);
  absl::Status InitializeOAuthTokenProviderMethods(JNIEnv* env,
                                                   jclass krypton_class);
  absl::Status InitializeTimerIdManager(JNIEnv* env, jclass krypton_class);
  absl::Status InitializeExceptions(JNIEnv* env);
  absl::Status InitializeNotifications(JNIEnv* env, jclass krypton_class);
  absl::Status InitializeVpnServiceMethods(JNIEnv* env, jclass krypton_class);
  absl::Status InitializeProvision(JNIEnv* env);

  jclass GetKryptonExceptionClass() const;

  JavaVM* java_vm_ = nullptr;

  // privacy.ppn.krypton.KryptonException
  std::unique_ptr<JavaClass> krypton_exception_class_;

  // privacy.ppn.krypton.HttpFetcher
  jmethodID http_fetcher_post_json_method_ = nullptr;
  jmethodID http_fetcher_lookup_dns_method_ = nullptr;

  // privacy.ppn.krypton.OAuthTokenProvider
  jmethodID oauth_token_provider_get_oauth_token_method_ = nullptr;
  jmethodID oauth_token_provider_get_attestation_data_method_ = nullptr;

  // privacy.ppn.krypton.TimerIdManager
  jmethodID timer_id_manager_start_timer_method_ = nullptr;
  jmethodID timer_id_manager_cancel_all_timers_method_ = nullptr;
  jmethodID timer_id_manager_cancel_timer_method_ = nullptr;

  // privacy.ppn.krypton.Krypton
  jmethodID krypton_get_oauth_token_provider_method_ = nullptr;
  jmethodID krypton_get_http_fetcher_method_ = nullptr;
  jmethodID krypton_get_timer_id_manager_method_ = nullptr;

  // Notification methods in KryptonImpl.java
  jmethodID krypton_connected_method_ = nullptr;
  jmethodID krypton_connecting_method_ = nullptr;
  jmethodID krypton_control_plane_connected_method_ = nullptr;
  jmethodID krypton_status_updated_method_ = nullptr;
  jmethodID krypton_disconnected_method_ = nullptr;
  jmethodID krypton_network_disconnected_method_ = nullptr;
  jmethodID krypton_permanent_failure_method_ = nullptr;
  jmethodID krypton_crashed_method_ = nullptr;
  jmethodID krypton_waiting_to_reconnect_method_ = nullptr;
  jmethodID krypton_create_tun_fd_method_ = nullptr;
  jmethodID krypton_create_network_fd_method_ = nullptr;
  jmethodID krypton_create_tcp_fd_method_ = nullptr;
  jmethodID krypton_configure_ipsec_method_ = nullptr;
  jmethodID krypton_snoozed_method_ = nullptr;
  jmethodID krypton_resumed_method_ = nullptr;

  // privacy.ppn.neon.Provision
  jmethodID provision_on_provisioned_method_ = nullptr;
  jmethodID provision_on_provisioning_failure_method_ = nullptr;
};

// Utility class that wraps a jobject (or subclass), holds a global reference to
// it, and deletes the global reference when it goes out of scope.
template <typename T>
class JavaObjectBase {
 public:
  explicit JavaObjectBase(T obj) {
    auto jni_cache = JniCache::Get();
    auto env = jni_cache->GetJavaEnv();
    if (!env) {
      LOG(ERROR) << "Cannot find JavaEnv to retain JavaObject.";
      return;
    }
    obj_ = static_cast<T>(env.value()->NewGlobalRef(obj));
  }

  JavaObjectBase(const JavaObjectBase& other) = delete;
  JavaObjectBase& operator=(const JavaObjectBase& other) = delete;
  JavaObjectBase(JavaObjectBase&& other) = delete;
  JavaObjectBase& operator=(JavaObjectBase&& other) = delete;

  ~JavaObjectBase() {
    auto jni_cache = JniCache::Get();
    auto env = jni_cache->GetJavaEnv();
    if (!env) {
      LOG(ERROR) << "Cannot find JavaEnv to release JavaObject.";
    }
    env.value()->DeleteGlobalRef(obj_);
  }

  T get() { return obj_; }

 private:
  T obj_;
};

using JavaObject = JavaObjectBase<jobject>;

// Utility class that converts a std::string to a Java String and owns the
// jstring's memory.
class JavaString : public JavaObjectBase<jstring> {
 public:
  JavaString(JNIEnv* env, const std::string& std_string)
      : JavaObjectBase(env->NewStringUTF(std_string.c_str())) {}
};

// Utility class that converts a std::string to a Java byte array and owns the
// byte array's memory.
class JavaByteArray : public JavaObjectBase<jbyteArray> {
 public:
  JavaByteArray(JNIEnv* env, const std::string& bytes)
      : JavaObjectBase(env->NewByteArray(bytes.size())) {
    // Copy the bytes into the newly created jbyteArray.
    env->SetByteArrayRegion(get(), 0, bytes.size(),
                            reinterpret_cast<const jbyte*>(bytes.data()));
  }
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_
