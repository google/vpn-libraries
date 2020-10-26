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

#include "privacy/net/krypton/jni/vpn_service.h"

#include <jni.h>
#include <jni_md.h>

#include <optional>
#include <string>

#include "base/logging.h"
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

absl::StatusOr<int> VpnService::CreateTunFd(const TunFdData& tun_fd_data) {
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
      jni_cache->GetKryptonObject(), jni_cache->GetKryptonCreateTunFdMethod(),
      JavaByteArray(env.value(), tun_fd_bytes).get());

  if (fd < 0) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        absl::StrCat("Unable to create TUN fd: ", fd));
  }
  return fd;
}

absl::StatusOr<int> VpnService::CreateNetworkFd(
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
      jni_cache->GetKryptonObject(),
      jni_cache->GetKryptonCreateNetworkFdMethod(),
      JavaByteArray(env.value(), network_info_bytes).get());

  if (fd < 0) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        absl::StrCat("Unable to create network fd: ", fd));
  }
  return fd;
}

absl::Status VpnService::ConfigureIpSec(const IpSecTransformParams& params) {
  LOG(INFO) << "Configuring IPSec for fd: " << params.network_fd();

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to configure IPSec.";
    absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  std::string transform_params_bytes;
  params.SerializeToString(&transform_params_bytes);
  jboolean status = env.value()->CallBooleanMethod(
      jni_cache->GetKryptonObject(),
      jni_cache->GetKryptonConfigureIpSecMethod(),
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
