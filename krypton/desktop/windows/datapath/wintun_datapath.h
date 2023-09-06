// Copyright 2022 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_DATAPATH_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_DATAPATH_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/desktop/windows/datapath/wintun_packet_forwarder.h"
#include "privacy/net/krypton/desktop/windows/rio_socket.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace windows {

// Manages the Wintun IPsec datapath on Windows.
// This class is thread-safe.
class WintunDatapath
    : public DatapathInterface,
      public WintunPacketForwarder::WintunNotificationInterface {
 public:
  class WintunVpnServiceInterface : public virtual VpnServiceInterface {
   public:
  };

  WintunDatapath(const KryptonConfig& config, Wintun* wintun,
                 krypton::utils::LooperThread* looper,
                 WintunVpnServiceInterface* vpn_service)
      : config_(config),
        wintun_(wintun),
        notification_thread_(looper),
        vpn_service_(vpn_service) {}
  ~WintunDatapath() override = default;
  // Delete copy, move, and their assign constructors.
  WintunDatapath(const WintunDatapath&) = delete;
  WintunDatapath(WintunDatapath&&) = delete;
  WintunDatapath& operator=(const WintunDatapath&) = delete;
  WintunDatapath& operator=(WintunDatapath&&) = delete;

  absl::Status Start(const AddEgressResponse& egress_response,
                     const TransformParams& params) override;

  void Stop() override;

  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             const NetworkInfo& network_info,
                             int counter) override;

  absl::Status SetKeyMaterials(const TransformParams& params) override;

  void PacketForwarderFailed(const absl::Status&) override;

  void PacketForwarderConnected() override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

 private:
  void ShutdownPacketForwarder() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Mutex mutex_;
  KryptonConfig config_;
  std::vector<std::string> private_ips_ ABSL_GUARDED_BY(mutex_);
  TransformParams key_material_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<RioSocket> network_socket_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<WintunPacketForwarder> packet_forwarder_
      ABSL_GUARDED_BY(mutex_);
  krypton::utils::LooperThread packet_forwarder_looper_{"PacketForwarder"};
  std::atomic_flag connected_;
  Wintun* wintun_;                                     // Not owned.
  krypton::utils::LooperThread* notification_thread_;  // Not owned.
  WintunVpnServiceInterface* vpn_service_;             // Not owned.
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_DATAPATH_H_
