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

#include "privacy/net/krypton/desktop/windows/vpn_service.h"

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/desktop/windows/datapath/wintun_datapath.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/desktop/windows/utils/networking.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::Status VpnService::InitializeWintun() {
  static absl::once_flag once;
  absl::Status status;
  absl::call_once(once, [this, &status]() {
    absl::MutexLock l(&mutex_);
    LOG(INFO) << "Initializing Wintun";
    status =  wintun_.Initialize();
    if (!status.ok()) {
      LOG(ERROR) << "Failed to initialize Wintun: " << status;
      return;
    }
    LOG(INFO) << "Initialized Wintun library";

    wintun_.SetAbslLogger();
    LOG(INFO) << "Started Wintun logging";

    // Create Wintun adapter.
    // TODO: localize strings in Wintun datapath.
    status = wintun_.CreateAdapter(/* name = */ "VPN by Google One",
                                   /* tunnel_type = */ "PPN");
    if (!status.ok()) {
      LOG(ERROR) << "Failed to create Wintun adapter: " << status;
      return;
    }
    LOG(INFO) << "Created Wintun adapter";
  });
  return status;
}

DatapathInterface* VpnService::BuildDatapath(
    const KryptonConfig& config, krypton::utils::LooperThread* looper,
    TimerManager* /* timer_manager */) {
  return new WintunDatapath(config, &wintun_, looper, this);
}

absl::Status VpnService::CreateTunnel(const TunFdData& /*tun_fd_data*/) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Creating tunnel";
  if (tunnel_interface_index_ >= 0) {
    return absl::AlreadyExistsError("Tunnel is already created");
  }

  // Add default route to Wintun adapter.
  PPN_ASSIGN_OR_RETURN(auto wintun_luid, wintun_.GetAdapterLUID());
  LOG(INFO) << "Got Wintun adapter LUID";
  PPN_ASSIGN_OR_RETURN(auto wintun_if_index,
                       utils::GetInterfaceIndexFromLuid(wintun_luid));
  LOG(INFO) << "Got Wintun adapter interface index: " << wintun_if_index;
  PPN_RETURN_IF_ERROR(
      utils::SetAdapterDefaultRoute(wintun_luid, wintun_if_index));
  LOG(INFO) << "Set default route to Wintun adapter";
  tunnel_interface_luid_ = wintun_luid;
  tunnel_interface_index_ = wintun_if_index;
  return absl::OkStatus();
}

void VpnService::CloseTunnel() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Closing tunnel";
  // Remove default route from Wintun adapter.
  if (tunnel_interface_index_ >= 0) {
    PPN_LOG_IF_ERROR(utils::RemoveAdapterDefaultRoute(tunnel_interface_luid_,
                                                      tunnel_interface_index_));
    tunnel_interface_index_ = -1;
  }
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
