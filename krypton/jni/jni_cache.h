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

#ifndef PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_
#define PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_

#include <jni.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace jni {

template <typename T>
class JavaObject;

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
  void Init(JNIEnv* env, jobject krypton_instance);

  // Current VM.
  JavaVM* GetJavaVm() const { return java_vm_; }

  // Retrieves the Java Environment to call the appropriate Java method.
  absl::optional<JNIEnv*> GetJavaEnv();

  // Throws exception to the java layer when krypton API is called.
  void ThrowKryptonException(const std::string& message);

  // com.google.android.libraries.privacy.ppn.krypton.HttpFetcher
  jobject GetHttpFetcherObject() const;
  jclass GetHttpFetcherClass() const;

  jmethodID GetHttpFetcherPostJsonMethod() const {
    return http_fetcher_post_json_method_;
  }

  // com.google.android.libraries.privacy.ppn.krypton.TimerIdManager
  jobject GetTimerIdManagerObject() const;
  jclass GetTimerIdManagerClass() const;
  jmethodID GetTimerIdManagerStartTimerMethod() const {
    return timer_id_manager_start_timer_method_;
  }
  jmethodID GetTimerIdManagerCancelTimerMethod() const {
    return timer_id_manager_cancel_timer_method_;
  }
  jmethodID GetTimerIdManagerCancelAllTimersMethod() const {
    return timer_id_manager_cancel_all_timers_method_;
  }

  // com.google.android.libraries.privacy.ppn.krypton.Krypton.
  jclass GetKryptonClass() const;
  jobject GetKryptonObject() const;
  jmethodID GetKryptonLogMethod() const { return krypton_log_method_; }
  jmethodID GetKryptonHttpFetcherMethod() const {
    return krypton_get_http_fetcher_method_;
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
  jmethodID GetKryptonCreateTunFdMethod() const {
    return krypton_create_tun_fd_method_;
  }
  jmethodID GetKryptonCreateNetworkFdMethod() const {
    return krypton_create_network_fd_method_;
  }
  jmethodID GetKryptonGetOAuthTokenMethod() const {
    return krypton_get_oauth_token_method_;
  }

  jmethodID GetKryptonConfigureIpSecMethod() const {
    return krypton_configure_ipsec_method_;
  }

 private:
  JniCache();
  ~JniCache() = default;

  // Initializes and fetches the corresponding Http Fetcher methods.
  void InitializeHttpFetcherMethod(JNIEnv* env);

  // Initializes and fetches the corresponding TimerIdManager methods.
  void InitializeTimerIdManager(JNIEnv* env);

  // Initializes and fetches the corresponding Logging methods.
  void InitializeLogMethod(JNIEnv* env);

  // Initializes the Log method.
  void InitializeExceptions(JNIEnv* env);

  // Initializes the notification methods.
  void InitializeNotifications(JNIEnv* env);

  // Initializes the createTunFd method.
  void InitializeCreateTunFdMethod(JNIEnv* env);

  // Initializes the createNetworkFd method.
  void InitializeCreateNetworkFdMethod(JNIEnv* env);

  // Initializes the getOAuthToken method.
  void InitializeGetOAuthTokenMethod(JNIEnv* env);

  void InitializeConfigureIpSecMethod(JNIEnv* env);

  jclass GetKryptonExceptionClass() const;

  JavaVM* java_vm_;
  std::unique_ptr<JavaObject<jclass>> krypton_exception_class_;

  // privacy.ppn.krypton.HttpFetcher
  std::unique_ptr<JavaObject<jclass>> http_fetcher_class_;
  std::unique_ptr<JavaObject<jobject>> http_fetcher_object_;
  jmethodID http_fetcher_post_json_method_;

  // privacy.ppn.krypton.TimerIdManager
  std::unique_ptr<JavaObject<jclass>> timer_id_manager_class_;
  std::unique_ptr<JavaObject<jobject>> timer_id_manager_object_;
  jmethodID timer_id_manager_start_timer_method_;
  jmethodID timer_id_manager_cancel_all_timers_method_;
  jmethodID timer_id_manager_cancel_timer_method_;

  // privacy.ppn.krypton.Krypton
  std::unique_ptr<JavaObject<jobject>> krypton_object_;
  std::unique_ptr<JavaObject<jclass>> krypton_class_;
  jmethodID krypton_log_method_;
  jmethodID krypton_get_http_fetcher_method_;

  // Notification methods in KryptonImpl.java
  jmethodID krypton_connected_method_;
  jmethodID krypton_connecting_method_;
  jmethodID krypton_control_plane_connected_method_;
  jmethodID krypton_status_updated_method_;
  jmethodID krypton_disconnected_method_;
  jmethodID krypton_network_disconnected_method_;
  jmethodID krypton_permanent_failure_method_;
  jmethodID krypton_crashed_method_;
  jmethodID krypton_waiting_to_reconnect_method_;
  jmethodID krypton_create_tun_fd_method_;
  jmethodID krypton_create_network_fd_method_;
  jmethodID krypton_get_oauth_token_method_;
  jmethodID krypton_configure_ipsec_method_;

 private:
  // TODO: Make it thread safe.
  absl::Mutex mutex_;
};

// Utility class that wraps a jobject (or subclass), holds a global reference to
// it, and deletes the global reference when it goes out of scope.
template <typename T>
class JavaObject {
 public:
  JavaObject(JNIEnv* env, T obj) {
    obj_ = static_cast<T>(env->NewGlobalRef(obj));
  }

  ~JavaObject() {
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

// Utility class that converts a std::string to a Java String and owns the
// jstring's memory.
class JavaString : public JavaObject<jstring> {
 public:
  JavaString(JNIEnv* env, const std::string& std_string)
      : JavaObject(env, env->NewStringUTF(std_string.c_str())) {}
};

// Utility class that converts a std::string to a Java byte array and owns the
// byte array's memory.
class JavaByteArray : public JavaObject<jbyteArray> {
 public:
  JavaByteArray(JNIEnv* env, const std::string& bytes)
      : JavaObject(env, env->NewByteArray(bytes.size())) {
    // Copy the bytes into the newly created jbyteArray.
    env->SetByteArrayRegion(get(), 0, bytes.size(),
                            reinterpret_cast<const jbyte*>(bytes.data()));
  }
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_JNI_CACHE_H_
