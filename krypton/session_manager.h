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

#ifndef PRIVACY_NET_KRYPTON_SESSION_MANAGER_H_
#define PRIVACY_NET_KRYPTON_SESSION_MANAGER_H_

#include <atomic>
#include <memory>
#include <optional>

#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager_interface.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

class KryptonDebugInfo;

// SessionManager manages the session.
class SessionManager : public SessionManagerInterface {
 public:
  SessionManager(const KryptonConfig& config,
                 HttpFetcherInterface* http_fetcher,
                 TimerManager* timer_manager, VpnServiceInterface* vpn_service,
                 OAuthInterface* oauth, TunnelManagerInterface* tunnel_manager,
                 utils::LooperThread* notification_thread);

  void RegisterNotificationInterface(Session::NotificationInterface*) override;
  void EstablishSession(int restart_count,
                        TunnelManagerInterface* tunnel_manager,
                        std::optional<NetworkInfo> network_info) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void TerminateSession(bool forceFailOpen) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status SetNetwork(std::optional<NetworkInfo> network_info) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void CollectTelemetry(KryptonTelemetry* telemetry);

  void GetDebugInfo(KryptonDebugInfo* debug_info) ABSL_LOCKS_EXCLUDED(mutex_);

  privacy::ppn::IpGeoLevel GetIpGeoLevel() ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return ip_geo_level_;
  }

  // Returns true if the geo level was set. Returns false if it was a no-op.
  bool SetIpGeoLevel(privacy::ppn::IpGeoLevel level)
      ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    if (ip_geo_level_ == level) {
      return false;
    }
    ip_geo_level_ = level;
    return true;
  }

 private:
  mutable absl::Mutex mutex_;

  KryptonConfig config_;
  privacy::ppn::IpGeoLevel ip_geo_level_ ABSL_GUARDED_BY(mutex_);

  HttpFetcherInterface* http_fetcher_;                // Not owned.
  Session::NotificationInterface* notification_;      // Not owned.
  TimerManager* timer_manager_;                       // Not owned.
  TunnelManagerInterface* tunnel_manager_;            // Not owned.
  VpnServiceInterface* vpn_service_;                  // Not owned.
  OAuthInterface* oauth_;                             // Not owned.
  utils::LooperThread* krypton_notification_thread_;  // Not owned.

  std::unique_ptr<Session> session_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<utils::LooperThread> looper_thread_ ABSL_GUARDED_BY(mutex_);
  std::atomic_bool session_created_ = false;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_SESSION_MANAGER_H_
