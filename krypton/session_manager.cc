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

#include "privacy/net/krypton/session_manager.h"

#include <atomic>
#include <memory>
#include <optional>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

SessionManager::SessionManager(const KryptonConfig& config,
                               HttpFetcherInterface* http_fetcher,
                               TimerManager* timer_manager,
                               VpnServiceInterface* vpn_service,
                               OAuthInterface* oauth,
                               TunnelManagerInterface* tunnel_manager,
                               utils::LooperThread* krypton_notification_thread)
    : config_(config),
      ip_geo_level_(config_.ip_geo_level()),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      tunnel_manager_(ABSL_DIE_IF_NULL(tunnel_manager)),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      oauth_(ABSL_DIE_IF_NULL(oauth)),
      krypton_notification_thread_(krypton_notification_thread) {}

void SessionManager::RegisterNotificationInterface(
    Session::NotificationInterface* interface) {
  notification_ = interface;
}

void SessionManager::EstablishSession(int restart_count,
                                      TunnelManagerInterface* tunnel_manager,
                                      std::optional<NetworkInfo> network_info) {
  if (session_created_) {
    LOG(INFO) << "Session is not terminated, terminating it now.";
    TerminateSession(/*forceFailOpen=*/false);
  }
  DCHECK(notification_) << "Notification needs to be set";
  absl::MutexLock l(&mutex_);
  looper_thread_ = std::make_unique<utils::LooperThread>(
      absl::StrCat("Session Looper ", restart_count));
  LOG(INFO) << "Creating " << restart_count << " session";
  KryptonConfig local_config = config_;
  local_config.set_ip_geo_level(ip_geo_level_);
  auto auth = std::make_unique<Auth>(local_config, http_fetcher_, oauth_);
  auto egress_manager =
      std::make_unique<EgressManager>(local_config, http_fetcher_);
  auto datapath =
      std::unique_ptr<DatapathInterface>(vpn_service_->BuildDatapath(
          local_config, looper_thread_.get(), timer_manager_));
  session_ = std::make_unique<Session>(
      local_config, std::move(auth), std::move(egress_manager),
      std::move(datapath), vpn_service_, timer_manager_, http_fetcher_,
      tunnel_manager, network_info, krypton_notification_thread_);
  session_->RegisterNotificationHandler(notification_);
  session_->Start();
  session_created_ = true;
}

void SessionManager::TerminateSession(bool forceFailOpen) {
  LOG(INFO) << "Calling Terminate Session";
  absl::MutexLock l(&mutex_);
  if (!session_created_) {
    LOG(ERROR) << "Session is not created.. Not terminating";
    tunnel_manager_->DatapathStopped(forceFailOpen);
    return;
  }
  LOG(INFO) << "Terminating Session";
  LOG(INFO) << "Stopping session looper thread ";
  if (looper_thread_ != nullptr) {
    looper_thread_->Stop();
    looper_thread_->Join();
  }
  LOG(INFO) << "Looper thread joined.";
  LOG(INFO) << "Stopping session";
  if (session_ != nullptr) {
    session_->Stop(forceFailOpen);
    session_.reset();
  }
  LOG(INFO) << "Session stopped";
  session_created_ = false;

  LOG(INFO) << "Session termination done.";
}

absl::Status SessionManager::SetNetwork(
    std::optional<NetworkInfo> network_info) {
  absl::MutexLock l(&mutex_);
  if (session_ == nullptr) {
    return absl::OkStatus();
  }
  return session_->SetNetwork(network_info);
}

void SessionManager::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  if (session_) {
    session_->CollectTelemetry(telemetry);
  }
}

void SessionManager::GetDebugInfo(KryptonDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  if (session_) {
    session_->GetDebugInfo(debug_info);
  }
}

}  // namespace krypton
}  // namespace privacy
