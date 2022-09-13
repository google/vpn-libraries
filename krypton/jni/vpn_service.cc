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

#include "privacy/net/krypton/jni/vpn_service.h"

#include <jni.h>
#include <jni_md.h>

#include <memory>
#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"

#include "privacy/net/krypton/fd_packet_pipe.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"

namespace privacy {
namespace krypton {
namespace jni {

DatapathInterface* VpnService::BuildDatapath(const KryptonConfig& config,
                                             utils::LooperThread* looper,
                                             TimerManager* /*timer_manager*/) {
  if (config.datapath_protocol() == KryptonConfig::IPSEC) {
    return new datapath::android::IpSecDatapath(looper, this);
  }
}

absl::Status VpnService::CreateTunnel(const TunFdData& tun_fd_data) {
  LOG(INFO) << "Requesting TUN fd from Java with tun data "
            << tun_fd_data.DebugString();

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request TUN fd";
    return absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  std::string tun_fd_bytes;
  tun_fd_data.SerializeToString(&tun_fd_bytes);

  jint fd = env.value()->CallIntMethod(
      krypton_instance_->get(), jni_cache->GetKryptonCreateTunFdMethod(),
      JavaByteArray(env.value(), tun_fd_bytes).get());

  if (fd < 0) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        absl::StrCat("Unable to create TUN fd: ", fd));
  }

  absl::MutexLock l(&mutex_);
  if (tunnel_ != nullptr) {
    LOG(WARNING) << "Old tunnel was still open. Closing now.";
    tunnel_->Close();
  }
  tunnel_ = std::make_unique<FdPacketPipe>(fd);
  return absl::OkStatus();
}

PacketPipe* VpnService::GetTunnel() {
  absl::MutexLock l(&mutex_);
  return tunnel_.get();
}

absl::StatusOr<int> VpnService::GetTunnelFd() {
  auto tunnel = GetTunnel();
  if (tunnel == nullptr) {
    return absl::InternalError("tunnel is null");
  }
  return tunnel->GetFd();
}

void VpnService::CloseTunnel() {
  absl::MutexLock l(&mutex_);
  if (tunnel_ == nullptr) {
    return;
  }
  tunnel_->Close();
  tunnel_.reset();
}

absl::StatusOr<int> VpnService::CreateProtectedNetworkSocket(
    const NetworkInfo& network_info) {
  LOG(INFO) << "Requesting network fd from Java with network info "
            << network_info.DebugString();

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request network fd";
    return absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  std::string network_info_bytes;
  network_info.SerializeToString(&network_info_bytes);

  jint fd = env.value()->CallIntMethod(
      krypton_instance_->get(), jni_cache->GetKryptonCreateNetworkFdMethod(),
      JavaByteArray(env.value(), network_info_bytes).get());

  if (fd < 0) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        absl::StrCat("Unable to create network fd: ", fd));
  }

  return fd;
}

absl::StatusOr<std::unique_ptr<PacketPipe>> VpnService::CreateNetworkPipe(
    const NetworkInfo& network_info, const Endpoint& endpoint) {
  PPN_ASSIGN_OR_RETURN(int fd, CreateProtectedNetworkSocket(network_info));

  auto pipe = std::make_unique<FdPacketPipe>(fd);
  auto status = pipe->Connect(endpoint);
  if (!status.ok()) {
    pipe->Close();
    return status;
  }
  return pipe;
}

absl::Status VpnService::ConfigureIpSec(const IpSecTransformParams& params) {
  LOG(INFO) << "Configuring IPSec for fd: " << params.network_fd();

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to configure IPSec.";
    return absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  std::string transform_params_bytes;
  params.SerializeToString(&transform_params_bytes);
  jboolean status = env.value()->CallBooleanMethod(
      krypton_instance_->get(), jni_cache->GetKryptonConfigureIpSecMethod(),
      JavaByteArray(env.value(), transform_params_bytes).get());
  if (static_cast<bool>(status)) {
    return absl::OkStatus();
  }
  return absl::Status(
      absl::StatusCode::kUnavailable,
      absl::StrCat("Error encountered when applying transform to fd: ",
                   params.network_fd()));
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
