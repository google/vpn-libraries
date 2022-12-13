/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_VPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_VPN_SERVICE_H_

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/desktop/windows/datapath/wintun_datapath.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

class VpnService : public WintunDatapath::WintunVpnServiceInterface {
 public:
  VpnService() = default;
  ~VpnService() override {
    // Shut down Wintun adapter.
    PPN_LOG_IF_ERROR(wintun_.CloseAdapter());
  }

  absl::Status InitializeWintun();

  // Builds a network-side pipe that reads and writes packets.
  DatapathInterface* BuildDatapath(const KryptonConfig& config,
                                   krypton::utils::LooperThread* looper,
                                   TimerManager* timer_manager) override;

  // Creates the tunnel with the given network settings.
  absl::Status CreateTunnel(const TunFdData& tun_fd_data) override;

  // Closes the current tunnel, disestablishing the VPN.
  void CloseTunnel() override;

 private:
  absl::Mutex mutex_;
  Wintun wintun_ ABSL_GUARDED_BY(mutex_);
  NET_LUID tunnel_interface_luid_ ABSL_GUARDED_BY(mutex_);
  int tunnel_interface_index_ ABSL_GUARDED_BY(mutex_) = -1;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_VPN_SERVICE_H_
