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

#include "privacy/net/krypton/session_manager.h"

#include <atomic>
#include <memory>

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
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

SessionManager::SessionManager(HttpFetcherInterface* http_fetcher,
                               TimerManager* timer_manager,
                               VpnServiceInterface* vpn_service,
                               OAuthInterface* oauth, KryptonConfig* config,
                               utils::LooperThread* krypton_notification_thread)
    : http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      oauth_(ABSL_DIE_IF_NULL(oauth)),
      config_(config),
      krypton_notification_thread_(krypton_notification_thread) {}

void SessionManager::RegisterNotificationInterface(
    Session::NotificationInterface* interface) {
  notification_ = interface;
}

void SessionManager::EstablishSession(
    absl::string_view zinc_url, absl::string_view brass_url,
    absl::string_view service_type, int restart_count,
    absl::optional<NetworkInfo> network_info) {
  if (session_created_) {
    LOG(INFO) << "Session is not terminated, terminating it now.";
    TerminateSession();
  }
  DCHECK(notification_) << "Notification needs to be set";
  absl::MutexLock l(&mutex_);
  looper_thread_ = absl::make_unique<utils::LooperThread>(
      absl::StrCat("Session Looper ", restart_count));
  LOG(INFO) << "Creating " << restart_count << " session";
  auth_ = absl::make_unique<Auth>(config_, http_fetcher_, oauth_,
                                  looper_thread_.get());
  egress_manager_ = absl::make_unique<EgressManager>(brass_url, http_fetcher_,
                                                     looper_thread_.get());

  // TODO: Initialize datapath_, once we have an implementation.

  session_ = absl::make_unique<Session>(
      auth_.get(), egress_manager_.get(), datapath_.get(), vpn_service_,
      timer_manager_, network_info, config_, krypton_notification_thread_);
  session_->RegisterNotificationHandler(notification_);
  session_->Start();
  session_created_ = true;
}

void SessionManager::TerminateSession() {
  LOG(INFO) << "Calling Terminate Session";
  absl::MutexLock l(&mutex_);
  if (!session_created_) {
    LOG(ERROR) << "Session is not created.. Not terminating";
    return;
  }
  LOG(INFO) << "Terminating Session";
  LOG(INFO) << "Stopping session looper thread ";
  if (looper_thread_ != nullptr) {
    looper_thread_->Stop();
    looper_thread_->Join();
  }
  LOG(INFO) << "Looper thread joined.";
  if (auth_ != nullptr) {
    auth_->Stop();
    auth_.reset();
  }
  LOG(INFO) << "Auth stopped";
  if (egress_manager_ != nullptr) {
    egress_manager_->Stop();
    egress_manager_.reset();
  }
  LOG(INFO) << "Egress stopped";

  LOG(INFO) << "Stopping datapath ";
  if (datapath_ != nullptr) {
    datapath_->Stop();
    datapath_.reset();
  }

  LOG(INFO) << "Stopping session";
  if (session_ != nullptr) {
    session_->Stop();
    session_.reset();
  }
  LOG(INFO) << "Session stopped";
  session_created_ = false;

  LOG(INFO) << "Session termination done.";
}

void SessionManager::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  if (auth_) {
    auth_->CollectTelemetry(telemetry);
  }
  if (egress_manager_) {
    egress_manager_->CollectTelemetry(telemetry);
  }
  if (session_) {
    session_->CollectTelemetry(telemetry);
  }
}

void SessionManager::GetDebugInfo(KryptonDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  if (auth_) {
    auth_->GetDebugInfo(debug_info->mutable_auth());
  }
  if (egress_manager_) {
    egress_manager_->GetDebugInfo(debug_info->mutable_egress());
  }
  if (session_) {
    session_->GetDebugInfo(debug_info->mutable_session());
  }
}

}  // namespace krypton
}  // namespace privacy
