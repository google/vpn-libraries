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

#include <jni.h>
#include <jni_md.h>

#include <string>

#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/jni/krypton_notification.h"
#include "privacy/net/krypton/jni/oauth.h"
#include "privacy/net/krypton/jni/vpn_service.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/ppn_status.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"

using privacy::krypton::ConnectingStatus;
using privacy::krypton::ConnectionStatus;
using privacy::krypton::DisconnectionStatus;
using privacy::krypton::IpSecTransformParams;
using privacy::krypton::NetworkInfo;
using privacy::krypton::PpnStatusDetails;
using privacy::krypton::ReconnectionStatus;
using privacy::krypton::ResumeStatus;
using privacy::krypton::SnoozeStatus;
using privacy::krypton::TunFdData;
using privacy::krypton::jni::ConvertJavaByteArrayToString;
using privacy::krypton::jni::ConvertJavaStringToUTF8;
using privacy::krypton::jni::JniCache;
using privacy::krypton::jni::KryptonNotification;
using privacy::krypton::jni::VpnService;
using privacy::krypton::utils::SetPpnStatusDetails;

// Implementations of native methods from JniTestNotification.java.
// LINT.IfChange
extern "C" {

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_connectedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray connection_status_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string connection_status_bytes =
      ConvertJavaByteArrayToString(env, connection_status_byte_array);
  ConnectionStatus connection_status;
  if (!connection_status.ParseFromString(connection_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid ConnectionStatus bytes");
    return;
  }

  notification.Connected(connection_status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_connectingNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray connecting_status_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string connecting_status_bytes =
      ConvertJavaByteArrayToString(env, connecting_status_byte_array);
  ConnectingStatus connecting_status;
  if (!connecting_status.ParseFromString(connecting_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid ConnectingStatus bytes");
    return;
  }

  notification.Connecting(connecting_status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_controlPlaneConnected(
    JNIEnv* /*env*/, jobject /*instance*/, jobject krypton_instance) {
  KryptonNotification notification(krypton_instance);
  notification.ControlPlaneConnected();
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_statusUpdatedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray connection_status_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string connection_status_bytes =
      ConvertJavaByteArrayToString(env, connection_status_byte_array);
  ConnectionStatus connection_status;
  if (!connection_status.ParseFromString(connection_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid ConnectionStatus bytes");
    return;
  }

  notification.StatusUpdated(connection_status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_disconnectedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray status_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string status_bytes =
      ConvertJavaByteArrayToString(env, status_byte_array);
  DisconnectionStatus status;
  if (!status.ParseFromString(status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid DisconnectionStatus bytes");
    return;
  }

  notification.Disconnected(status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_permanentFailureNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance, jint code,
    jstring message, jbyteArray details_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string details_bytes =
      ConvertJavaByteArrayToString(env, details_byte_array);
  PpnStatusDetails details;
  if (!details.ParseFromString(details_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid PpnStatusDetails bytes");
    return;
  }

  absl::Status status(static_cast<absl::StatusCode>(code),
                      ConvertJavaStringToUTF8(env, message));
  SetPpnStatusDetails(&status, details);
  notification.PermanentFailure(status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_networkDisconnectedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray network_info_byte_array, jint code, jstring message,
    jbyteArray details_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string details_bytes =
      ConvertJavaByteArrayToString(env, details_byte_array);
  PpnStatusDetails details;
  if (!details.ParseFromString(details_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid PpnStatusDetails bytes");
    return;
  }

  std::string network_info_bytes =
      ConvertJavaByteArrayToString(env, network_info_byte_array);
  NetworkInfo network_info;
  if (!network_info.ParseFromString(network_info_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid NetworkInfo bytes");
    return;
  }

  absl::Status status(static_cast<absl::StatusCode>(code),
                      ConvertJavaStringToUTF8(env, message));
  SetPpnStatusDetails(&status, details);
  notification.NetworkDisconnected(network_info, status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_waitingToReconnectNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray reconnection_status_byte_array) {
  KryptonNotification notification(krypton_instance);

  std::string reconnection_status_bytes =
      ConvertJavaByteArrayToString(env, reconnection_status_byte_array);
  ReconnectionStatus reconnection_status;
  if (!reconnection_status.ParseFromString(reconnection_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid ReconnectionStatus bytes");
    return;
  }

  notification.WaitingToReconnect(reconnection_status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_snoozedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray snooze_status_byte_array) {
  KryptonNotification notification(krypton_instance);
  std::string snooze_status_bytes =
      ConvertJavaByteArrayToString(env, snooze_status_byte_array);
  SnoozeStatus status;
  if (!status.ParseFromString(snooze_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid SnoozeStatus bytes");
  }
  notification.Snoozed(status);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_resumedNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray resume_status_byte_array) {
  KryptonNotification notification(krypton_instance);
  std::string resume_status_bytes =
      ConvertJavaByteArrayToString(env, resume_status_byte_array);
  ResumeStatus status;
  if (!status.ParseFromString(resume_status_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid ResumeStatus bytes");
  }
  notification.Resumed(status);
}

JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_createTunFdNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray tun_fd_data_byte_array) {
  VpnService service(krypton_instance);
  std::string tun_fd_data_bytes =
      ConvertJavaByteArrayToString(env, tun_fd_data_byte_array);
  TunFdData tun_fd_data;
  if (!tun_fd_data.ParseFromString(tun_fd_data_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid TunFdData bytes");
    return -1;
  }
  auto status = service.CreateTunnel(tun_fd_data);
  if (!status.ok()) {
    JniCache::Get()->ThrowKryptonException(status.ToString());
    return -1;
  }
  auto fd = service.GetTunnelFd();
  if (!fd.ok()) {
    JniCache::Get()->ThrowKryptonException(fd.status().ToString());
    return -1;
  }
  service.CloseTunnel();
  return *fd;
}

JNIEXPORT jint JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_createNetworkFdNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray network_info_byte_array) {
  VpnService service(krypton_instance);
  std::string network_info_bytes =
      ConvertJavaByteArrayToString(env, network_info_byte_array);
  NetworkInfo network_info;
  if (!network_info.ParseFromString(network_info_bytes)) {
    JniCache::Get()->ThrowKryptonException("invalid NetworkInfo bytes");
    return -1;
  }
  auto fd = service.CreateProtectedNetworkSocket(network_info);
  if (!fd.ok()) {
    JniCache::Get()->ThrowKryptonException(fd.status().ToString());
    return -1;
  }
  return *fd;
}

JNIEXPORT jboolean JNICALL
Java_com_google_android_libraries_privacy_ppn_krypton_JniTestNotification_configureIpSecNative(
    JNIEnv* env, jobject /*instance*/, jobject krypton_instance,
    jbyteArray ipsec_transform_params_byte_array) {
  VpnService service(krypton_instance);
  std::string ipsec_transform_params_bytes =
      ConvertJavaByteArrayToString(env, ipsec_transform_params_byte_array);
  IpSecTransformParams params;
  if (!params.ParseFromString(ipsec_transform_params_bytes)) {
    JniCache::Get()->ThrowKryptonException(
        "invalid IpSecTransformParams bytes");
    return 0u;
  }
  return static_cast<jboolean>(service.ConfigureIpSec(params).ok());
}

}  // extern "C"
// LINT.ThenChange(//depot/google3/javatests/com/google/android/libraries/privacy/ppn/krypton/JniTestNotification.java)
