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

#ifndef PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_

#include <jni.h>

#include <memory>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_tunnel.h"

#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/socket_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace jni {

class VpnService
    : public datapath::android::IpSecDatapath::IpSecVpnServiceInterface
 {
 public:
  explicit VpnService(jobject krypton_instance)
      : krypton_instance_(std::make_unique<JavaObject>(krypton_instance)),
        tunnel_fd_(-1),
        keepalive_interval_ipv4_(absl::ZeroDuration()),
        keepalive_interval_ipv6_(absl::ZeroDuration()) {}

  DatapathInterface* BuildDatapath(const KryptonConfig& config,
                                   utils::LooperThread* looper,
                                   TimerManager* timer_manager) override;

  // TUN fd creation
  absl::Status CreateTunnel(const TunFdData& tun_fd_data) override;
  datapath::android::TunnelInterface* GetTunnel() override;
  absl::StatusOr<int> GetTunnelFd() override;
  void CloseTunnel() override;

  // Network fd creation
  absl::StatusOr<int> CreateProtectedNetworkSocket(
      const NetworkInfo& network_info) override;
  absl::StatusOr<int> CreateProtectedTcpSocket(
      const NetworkInfo& network_info) override;

  absl::StatusOr<std::unique_ptr<SocketInterface>> ConfigureNetworkSocket(
      int fd, const Endpoint& endpoint) override;

  absl::Status ConfigureIpSec(const IpSecTransformParams& params) override;

  void DisableKeepalive() override;

 private:
  std::unique_ptr<JavaObject> krypton_instance_;

  absl::Mutex mutex_;
  std::unique_ptr<datapath::android::IpSecTunnel> tunnel_
      ABSL_GUARDED_BY(mutex_);
  int tunnel_fd_ ABSL_GUARDED_BY(mutex_);

  absl::Duration keepalive_interval_ipv4_;
  absl::Duration keepalive_interval_ipv6_;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_VPN_SERVICE_H_
