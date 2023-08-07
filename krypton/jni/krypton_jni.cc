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

// Please have all JNI methods listed below.  "extern C" is needed to ensure
// it's C method that Java can call.
#include <jni.h>
#include <jni_md.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/jni/http_fetcher.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_timer_interface_impl.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/jni/krypton_notification.h"
#include "privacy/net/krypton/jni/oauth.h"
#include "privacy/net/krypton/jni/vpn_service.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/time/time.h"

using privacy::krypton::Krypton;
using privacy::krypton::KryptonConfig;
using privacy::krypton::KryptonDebugInfo;
using privacy::krypton::KryptonTelemetry;
using privacy::krypton::NetworkInfo;
using privacy::krypton::TimerManager;
using privacy::krypton::jni::ConvertJavaByteArrayToString;
using privacy::krypton::jni::HttpFetcher;
using privacy::krypton::jni::JniCache;
using privacy::krypton::jni::JniTimerInterfaceImpl;
using privacy::krypton::jni::KryptonNotification;
using privacy::krypton::jni::OAuth;
using privacy::krypton::jni::VpnService;

// Implementations of native methods from KryptonImpl.java.
// LINT.IfChange
extern "C" {

// Initialize the Krypton library.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_init(
    JNIEnv* env, jobject krypton_instance);

// Start the Krypton library.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_startNative(
    JNIEnv* env, jobject krypton_instance, jbyteArray config_bytes);

// Stop the Krypton library.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_stopNative(
    JNIEnv* env, jobject krypton_instance);

// Switch API for switching across different access networks.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setNetworkNative(
    JNIEnv* env, jobject krypton_instance, jbyteArray request_byte_array);

// setNoNetworkAvailable API indicating there are no active networks.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setNoNetworkAvailable(
    JNIEnv* env, jobject krypton_instance);

// Timer expiry
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_timerExpired(
    JNIEnv* env, jobject krypton_instance, int timer_id);

// Snooze
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_snooze(
    JNIEnv* env, jobject krypton_instance, int snooze_duration_ms);

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_extendSnooze(
    JNIEnv* env, jobject krypton_instance, int extend_snooze_duration_ms);

// Resume
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_resume(
    JNIEnv* env, jobject krypton_instance);

// SetSafeDisconnectEnabled
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setSafeDisconnectEnabled(
    JNIEnv* env, jobject krypton_instance, jboolean enable);

// IsSafeDisconnectEnabled
JNIEXPORT bool JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_isSafeDisconnectEnabled(
    JNIEnv* env, jobject krypton_instance);

// SetIpGeoLevel
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setIpGeoLevelNative(
    JNIEnv* env, jobject krypton_instance, jint level);

// GetIpGeoLevel
JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_getIpGeoLevelNative(
    JNIEnv* env, jobject krypton_instance);

// SetSimulatedNetworkFailure
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setSimulatedNetworkFailure(
    JNIEnv* env, jobject krypton_instance, jboolean simulated_network_failure);

// CollectTelemetry
JNIEXPORT jbyteArray JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_collectTelemetryNative(
    JNIEnv* env, jobject krypton_instance);

// GetDebugInfo
JNIEXPORT jbyteArray JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_getDebugInfoNative(
    JNIEnv* env, jobject krypton_instance);

// DisableKeepalive
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_disableKryptonKeepaliveNative(
    JNIEnv* env, jobject krypton_instance);

// Update the TUN interface
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_forceTunnelUpdateNative(
    JNIEnv* env, jobject krypton_instance);
}
// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/krypton/KryptonImpl.java)

namespace {

// Local scope krypton instance.  There should only be one krypton instance
// running at any given time.
struct KryptonCache {
 public:
  KryptonCache(jobject krypton_instance, jobject http_fetcher_instance,
               jobject oauth_token_provider_instance,
               jobject timer_manager_id_instance) {
    http_fetcher = std::make_unique<HttpFetcher>(http_fetcher_instance);
    notification = std::make_unique<KryptonNotification>(krypton_instance);
    vpn_service = std::make_unique<VpnService>(krypton_instance);
    oauth = std::make_unique<OAuth>(oauth_token_provider_instance);
    jni_timer_interface =
        std::make_unique<JniTimerInterfaceImpl>(timer_manager_id_instance);
    timer_manager = std::make_unique<TimerManager>(jni_timer_interface.get());
  }

  ~KryptonCache() {
    // Order of deletion matters as there could be some pending API calls. Start
    // with Krypton.
    krypton.reset();
    notification.reset();
    vpn_service.reset();
    oauth.reset();
    http_fetcher.reset();
    // jni_timer_interface needs to be reset so that we don't get notifications
    // from Java.
    jni_timer_interface.reset();
    timer_manager.reset();
  }
  std::unique_ptr<JniTimerInterfaceImpl> jni_timer_interface;
  std::unique_ptr<TimerManager> timer_manager;
  std::unique_ptr<Krypton> krypton;
  std::unique_ptr<HttpFetcher> http_fetcher;
  std::unique_ptr<KryptonNotification> notification;
  std::unique_ptr<VpnService> vpn_service;
  std::unique_ptr<OAuth> oauth;
};

std::unique_ptr<KryptonCache> krypton_cache;

}  // namespace

// Krypton Initialization
// If Init is called when there is an active krypton instance, the older
// instance is terminated and a new gets to start.
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_init(
    JNIEnv* env, jobject krypton_instance) {
  // Fetch the VM and store the krypton java object
  auto jni_ppn = privacy::krypton::jni::JniCache::Get();
  jni_ppn->Init(env);

  // Initialize the Krypton library.
  LOG(INFO) << "Initializing the Krypton native library";
  if (krypton_cache != nullptr) {
    LOG(INFO) << "Resetting the cached Krypton instance.";
    krypton_cache->krypton->Stop();
    krypton_cache.reset();
  }

  LOG(INFO) << "Getting HttpFetcher instance.";
  jobject http_fetcher_instance = static_cast<jobject>(env->CallObjectMethod(
      krypton_instance, jni_ppn->GetKryptonGetHttpFetcherMethod()));
  if (http_fetcher_instance == nullptr) {
    LOG(FATAL) << "Unable to load HttpFetcher instance.";
  }

  LOG(INFO) << "Getting OAuthTokenProvider instance.";
  jobject oauth_token_provider_instance =
      static_cast<jobject>(env->CallObjectMethod(
          krypton_instance, jni_ppn->GetKryptonGetOAuthTokenProviderMethod()));
  if (oauth_token_provider_instance == nullptr) {
    LOG(FATAL) << "Unable to load OAuthTokenProvider instance.";
  }

  LOG(INFO) << "Getting TimerIdManager instance.";
  jobject timer_id_manager_instance =
      static_cast<jobject>(env->CallObjectMethod(
          krypton_instance, jni_ppn->GetKryptonGetTimerIdManagerMethod()));
  if (timer_id_manager_instance == nullptr) {
    LOG(FATAL) << "Unable to load TimerIdManager instance.";
  }

  // Create the new Krypton object and make it the singleton.
  krypton_cache = std::make_unique<KryptonCache>(
      krypton_instance, http_fetcher_instance, oauth_token_provider_instance,
      timer_id_manager_instance);
  krypton_cache->krypton = std::make_unique<privacy::krypton::Krypton>(
      krypton_cache->http_fetcher.get(), krypton_cache->notification.get(),
      krypton_cache->vpn_service.get(), krypton_cache->oauth.get(),
      krypton_cache->timer_manager.get());
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_startNative(
    JNIEnv* env, jobject /*krypton_instance*/, jbyteArray config_byte_array) {
  LOG(INFO) << "Starting Krypton native library";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton was not initialized.");
    return;
  }

  // Parse the config.
  KryptonConfig config;
  std::string config_bytes =
      ConvertJavaByteArrayToString(env, config_byte_array);
  if (!config.ParseFromString(config_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid KryptonConfig bytes");
    return;
  }

  krypton_cache->krypton->Start(config);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_stopNative(
    JNIEnv* /*env*/, jobject /*thiz*/) {
  // Initialize the Krypton library.
  LOG(INFO) << "Stopping Krypton native library";
  if (krypton_cache != nullptr) {
    krypton_cache->krypton->Stop();
    krypton_cache.reset();
  }
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setNoNetworkAvailable(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  LOG(INFO) << "SetNoNetworkAvailable is called";

  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }

  auto status = krypton_cache->krypton->SetNoNetworkAvailable();
  if (!status.ok()) {
    JniCache::Get()->ThrowKryptonException(status.ToString());
    return;
  }
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setNetworkNative(
    JNIEnv* env, jobject /*krypton_instance*/, jbyteArray request_byte_array) {
  NetworkInfo request;
  std::string request_bytes =
      ConvertJavaByteArrayToString(env, request_byte_array);
  if (!request.ParseFromString(request_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid NetworkInfo bytes");
    return;
  }

  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }

  auto status = krypton_cache->krypton->SetNetwork(request);
  if (!status.ok()) {
    JniCache::Get()->ThrowKryptonException(status.ToString());
    return;
  }
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_timerExpired(
    JNIEnv* /*env*/, jobject /*krypton_instance*/, int timer_id) {
  if (krypton_cache == nullptr || krypton_cache->timer_manager == nullptr) {
    JniCache::Get()->ThrowKryptonException(
        "Krypton or TimerManager is not running");
    return;
  }
  krypton_cache->jni_timer_interface->TimerExpiry(timer_id);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_snooze(
    JNIEnv* /*env*/, jobject /*krypton_instance*/, int snooze_duration_ms) {
  if (krypton_cache == nullptr || krypton_cache->timer_manager == nullptr) {
    JniCache::Get()->ThrowKryptonException(
        "Krypton or TimerManager is not running");
    return;
  }
  krypton_cache->krypton->Snooze(absl::Milliseconds(snooze_duration_ms));
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_extendSnooze(
    JNIEnv* /*env*/, jobject /*krypton_instance*/,
    int extend_snooze_duration_ms) {
  if (krypton_cache == nullptr || krypton_cache->timer_manager == nullptr) {
    JniCache::Get()->ThrowKryptonException(
        "Krypton or TimerManager is not running");
    return;
  }
  krypton_cache->krypton->ExtendSnooze(
      absl::Milliseconds(extend_snooze_duration_ms));
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_resume(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  if (krypton_cache == nullptr || krypton_cache->timer_manager == nullptr) {
    JniCache::Get()->ThrowKryptonException(
        "Krypton or TimerManager is not running");
    return;
  }
  krypton_cache->krypton->Resume();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setSafeDisconnectEnabled(
    JNIEnv* /*env*/, jobject /*krypton_instance*/, jboolean enable) {
  LOG(INFO) << "setSafeDisconnectEnabled is called";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }
  krypton_cache->krypton->SetSafeDisconnectEnabled(enable != 0u);
}

JNIEXPORT bool JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_isSafeDisconnectEnabled(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  LOG(INFO) << "isSafeDisconnectEnabled is called";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return false;
  }
  return krypton_cache->krypton->IsSafeDisconnectEnabled();
}

// SetIpGeoLevel
JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setIpGeoLevelNative(
    JNIEnv* /*env*/, jobject /*krypton_instance*/, jint level) {
  LOG(INFO) << "setIpGeoLevel is called";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }
  krypton_cache->krypton->SetIpGeoLevel(
      static_cast<privacy::ppn::IpGeoLevel>(level));
}

// GetIpGeoLevel
JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_getIpGeoLevelNative(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  LOG(INFO) << "getIpGeoLevel is called";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return privacy::ppn::IP_GEO_LEVEL_UNSPECIFIED;
  }
  return krypton_cache->krypton->GetIpGeoLevel();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_setSimulatedNetworkFailure(
    JNIEnv* /*env*/, jobject /*krypton_instance*/,
    jboolean simulated_network_failure) {
  LOG(INFO) << "setSimulatedNetworkFailure is called";
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }
  krypton_cache->krypton->SetSimulatedNetworkFailure(
      simulated_network_failure != 0u);
}

JNIEXPORT jbyteArray JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_collectTelemetryNative(
    JNIEnv* env, jobject /*krypton_instance*/) {
  LOG(INFO) << "collectTelemetry is called";

  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return env->NewByteArray(0);
  }

  KryptonTelemetry telemetry;
  krypton_cache->krypton->CollectTelemetry(&telemetry);
  std::string bytes = telemetry.SerializeAsString();

  // We can't use JavaArray here, because we need to return the local reference.
  jbyteArray array = env->NewByteArray(bytes.size());
  env->SetByteArrayRegion(array, 0, bytes.size(),
                          reinterpret_cast<const jbyte*>(bytes.data()));
  return array;
}

JNIEXPORT jbyteArray JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_getDebugInfoNative(
    JNIEnv* env, jobject /*krypton_instance*/) {
  LOG(INFO) << "getDebugInfoBytes is called";

  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return env->NewByteArray(0);
  }

  KryptonDebugInfo debug_info;
  krypton_cache->krypton->GetDebugInfo(&debug_info);
  std::string bytes = debug_info.SerializeAsString();

  // We can't use JavaArray here, because we need to return the local reference.
  jbyteArray array = env->NewByteArray(bytes.size());
  env->SetByteArrayRegion(array, 0, bytes.size(),
                          reinterpret_cast<const jbyte*>(bytes.data()));
  return array;
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_disableKryptonKeepaliveNative(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  if (krypton_cache == nullptr || krypton_cache->vpn_service == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }
  krypton_cache->vpn_service->DisableKeepalive();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_KryptonImpl_forceTunnelUpdateNative(
    JNIEnv* /*env*/, jobject /*krypton_instance*/) {
  if (krypton_cache == nullptr || krypton_cache->krypton == nullptr) {
    JniCache::Get()->ThrowKryptonException("Krypton is not running");
    return;
  }
  krypton_cache->krypton->ForceTunnelUpdate();
}
