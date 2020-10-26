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

#include <jni.h>
#include <jni_md.h>

#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/jni/krypton_notification.h"
#include "privacy/net/krypton/jni/oauth.h"
#include "privacy/net/krypton/jni/vpn_service.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/status.h"

using privacy::krypton::IpSecTransformParams;
using privacy::krypton::NetworkInfo;
using privacy::krypton::TunFdData;
using privacy::krypton::jni::ConvertJavaByteArrayToString;
using privacy::krypton::jni::ConvertJavaStringToUTF8;
using privacy::krypton::jni::JavaString;
using privacy::krypton::jni::JniCache;
using privacy::krypton::jni::KryptonNotification;
using privacy::krypton::jni::OAuth;
using privacy::krypton::jni::VpnService;

// Implementations of native methods from JniTestNotification.java.
// LINT.IfChange
extern "C" {

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_connected(
    JNIEnv* env, jobject instance) {
  KryptonNotification notification;
  notification.Connected();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_connecting(
    JNIEnv* env, jobject instance) {
  KryptonNotification notification;
  notification.Connecting();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_controlPlaneConnected(
    JNIEnv* env, jobject instance) {
  KryptonNotification notification;
  notification.ControlPlaneConnected();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_statusUpdated(
    JNIEnv* env, jobject instance) {
  KryptonNotification notification;
  notification.StatusUpdated();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_disconnectedNative(
    JNIEnv* env, jobject instance, jint code, jstring message) {
  KryptonNotification notification;
  absl::Status status(static_cast<absl::StatusCode>(code),
                      ConvertJavaStringToUTF8(env, message));
  notification.Disconnected(status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_permanentFailureNative(
    JNIEnv* env, jobject instance, jint code, jstring message) {
  KryptonNotification notification;
  absl::Status status(static_cast<absl::StatusCode>(code),
                      ConvertJavaStringToUTF8(env, message));
  notification.PermanentFailure(status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_networkDisconnectedNative(
    JNIEnv* env, jobject instance, jbyteArray network_info_byte_array,
    jint code, jstring message) {
  KryptonNotification notification;
  std::string network_info_bytes =
      ConvertJavaByteArrayToString(env, network_info_byte_array);
  NetworkInfo network_info;
  if (!network_info.ParseFromString(network_info_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid NetworkInfo bytes");
    return;
  }
  absl::Status status(static_cast<absl::StatusCode>(code),
                      ConvertJavaStringToUTF8(env, message));
  notification.NetworkDisconnected(network_info, status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_waitingToReconnectNative(
    JNIEnv* env, jobject instance, jlong retry_millis) {
  KryptonNotification notification;
  notification.WaitingToReconnect(retry_millis);
}

JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_createTunFdNative(
    JNIEnv* env, jobject instance, jbyteArray tun_fd_data_byte_array) {
  VpnService service;
  std::string tun_fd_data_bytes =
      ConvertJavaByteArrayToString(env, tun_fd_data_byte_array);
  TunFdData tun_fd_data;
  if (!tun_fd_data.ParseFromString(tun_fd_data_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid TunFdData bytes");
    return -1;
  }
  auto status_or_fd = service.CreateTunFd(tun_fd_data);
  if (!status_or_fd.ok()) {
    JniCache::Get()->ThrowKryptonException(status_or_fd.status().ToString());
    return -1;
  }
  return status_or_fd.value();
}

JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_createNetworkFdNative(
    JNIEnv* env, jobject instance, jbyteArray network_info_byte_array) {
  VpnService service;
  std::string network_info_bytes =
      ConvertJavaByteArrayToString(env, network_info_byte_array);
  NetworkInfo network_info;
  if (!network_info.ParseFromString(network_info_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid NetworkInfo bytes");
    return -1;
  }
  auto status_or_fd = service.CreateNetworkFd(network_info);
  if (!status_or_fd.ok()) {
    JniCache::Get()->ThrowKryptonException(status_or_fd.status().ToString());
    return -1;
  }
  return status_or_fd.value();
}

JNIEXPORT jstring JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_getOAuthToken(
    JNIEnv* env, jobject instance) {
  OAuth oauth;
  auto status_or_token = oauth.GetOAuthToken();
  std::string token = "";
  if (!status_or_token.ok()) {
    JniCache::Get()->ThrowKryptonException(status_or_token.status().ToString());
    return env->NewStringUTF("");
  }
  // We can't use JavaString here, because we need to return the local
  // reference.
  return env->NewStringUTF(status_or_token.value().c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_configureIpSecNative(
    JNIEnv* env, jobject instance,
    jbyteArray ipsec_transform_params_byte_array) {
  VpnService service;
  std::string ipsec_transform_params_bytes =
      ConvertJavaByteArrayToString(env, ipsec_transform_params_byte_array);
  IpSecTransformParams params;
  if (!params.ParseFromString(ipsec_transform_params_bytes)) {
    JniCache::Get()->ThrowKryptonException(
        "invalid IpSecTransformParams bytes");
    return false;
  }
  return service.ConfigureIpSec(params).ok();
}

}  // extern "C"
// LINT.ThenChange(//depot/google3/javatests/com/google/android/libraries/privacy/ppn/krypton/JniTestNotification.java)
