// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/tunnel_manager.h"

#include <cstddef>
#include <memory>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/utils/proto_comparison.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {

TunnelManager::TunnelManager(VpnServiceInterface* vpn_service,
                             bool safe_disconnect_enabled)
    : vpn_service_(ABSL_DIE_IF_NULL(vpn_service)) {
  safe_disconnect_enabled_ = safe_disconnect_enabled;
  session_active_ = false;
}

TunnelManager::~TunnelManager() {
  if (active_tunnel_) {
    active_tunnel_->Close();
  }
}

absl::Status TunnelManager::Start() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "TunnelManager started with Safe Disconnect: "
            << safe_disconnect_enabled_;
  return absl::OkStatus();
}

void TunnelManager::Stop() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "TunnelManager stopping";
  if (active_tunnel_) {
    LOG(INFO) << "TunnelManager closing active tunnel";
    active_tunnel_->Close();
    active_tunnel_.reset();
  }
  session_active_ = false;
}

void TunnelManager::SetSafeDisconnectEnabled(bool enable) {
  absl::MutexLock l(&mutex_);
  safe_disconnect_enabled_ = enable;
  LOG(INFO) << "TunnelManager set Safe Disconnect to " << enable;
  if (!session_active_ && active_tunnel_) {
    LOG(INFO) << "TunnelManager closing active tunnel";
    active_tunnel_->Close();
    active_tunnel_.reset();
  }
}

void TunnelManager::StartSession() {
  absl::MutexLock l(&mutex_);
  session_active_ = true;
  LOG(INFO) << "TunnelManager registered an active session";
}

absl::StatusOr<PacketPipe*> TunnelManager::GetTunnel(TunFdData tunnel_data) {
  // When Session is active, it can only change its tunnel by calling GetTunnel.
  absl::MutexLock l(&mutex_);
  if (active_tunnel_ && active_tunnel_data_.has_value() &&
      utils::TunFdDataEquiv(tunnel_data, active_tunnel_data_.value())) {
    LOG(INFO) << "TunnelManager returning existing tunnel";
    return active_tunnel_.get();
  }
  PPN_ASSIGN_OR_RETURN(auto tunnel, vpn_service_->CreateTunnel(tunnel_data));
  LOG(INFO) << "TunnelManager created a new tunnel";
  if (active_tunnel_) {
    LOG(INFO) << "TunnelManager closing previous active tunnel";
    active_tunnel_->Close();
    active_tunnel_.reset();
  }
  active_tunnel_ = std::move(tunnel);
  active_tunnel_data_ = tunnel_data;
  return active_tunnel_.get();
}

absl::Status TunnelManager::RecreateTunnelIfNeeded() {
  absl::MutexLock l(&mutex_);
  if (!safe_disconnect_enabled_) {
    LOG(INFO) << "Safe disconnect not enabled so will not recreate tunnel.";
    return absl::OkStatus();
  }
  if (active_tunnel_) {
    LOG(INFO) << "Tunnel already present, do not need to create another.";
    return absl::OkStatus();
  }
  if (active_tunnel_data_.has_value()) {
    LOG(INFO) << "Recreating tunnel.";
    PPN_ASSIGN_OR_RETURN(active_tunnel_,
                         vpn_service_->CreateTunnel(*active_tunnel_data_));
  }
  return absl::OkStatus();
}

void TunnelManager::TerminateSession(bool forceFailOpen) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "TunnelManager registered terminating session, Safe Disconnect: "
            << safe_disconnect_enabled_;
  if (active_tunnel_ && (forceFailOpen || !safe_disconnect_enabled_)) {
    LOG(INFO) << "TunnelManager closing active tunnel";
    active_tunnel_->Close();
    active_tunnel_.reset();
  }
  session_active_ = false;
}

bool TunnelManager::IsTunnelActive() {
  absl::MutexLock l(&mutex_);
  if (active_tunnel_) {
    LOG(INFO) << "Tunnel is active";
    return true;
  }
  LOG(INFO) << "Tunnel is not active";
  return false;
}

PacketPipe* TunnelManager::active_tunnel_test_only() const {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "TunnelManager returning active tunnel for test";
  if (active_tunnel_) {
    return active_tunnel_.get();
  }
  return nullptr;
}

}  // namespace krypton
}  // namespace privacy
