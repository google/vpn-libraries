// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_H_
#define PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_H_

#include <memory>
#include <optional>

#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {

class TunnelManager : public TunnelManagerInterface {
 public:
  TunnelManager(VpnServiceInterface* vpn_service, bool safe_disconnect_enabled);
  ~TunnelManager() override;

  absl::Status Start() override ABSL_LOCKS_EXCLUDED(mutex_);
  void Stop() override ABSL_LOCKS_EXCLUDED(mutex_);
  void SetSafeDisconnectEnabled(bool enable) override
      ABSL_LOCKS_EXCLUDED(mutex_);
  bool IsSafeDisconnectEnabled() override ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return safe_disconnect_enabled_;
  };

  void StartSession() override ABSL_LOCKS_EXCLUDED(mutex_);
  absl::Status EnsureTunnelIsUp(TunFdData) override ABSL_LOCKS_EXCLUDED(mutex_);
  absl::Status RecreateTunnelIfNeeded() override ABSL_LOCKS_EXCLUDED(mutex_);

  void TerminateSession(bool forceFailOpen) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  bool IsTunnelActive() override ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  mutable absl::Mutex mutex_;
  VpnServiceInterface* vpn_service_;  // Not owned.

  bool tunnel_is_up_ ABSL_GUARDED_BY(mutex_);
  std::optional<TunFdData> active_tunnel_data_ ABSL_GUARDED_BY(mutex_);
  bool safe_disconnect_enabled_ ABSL_GUARDED_BY(mutex_);
  bool session_active_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_H_
