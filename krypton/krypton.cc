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

#include "privacy/net/krypton/krypton.h"

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/session_manager.h"
#include "privacy/net/krypton/tunnel_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {

void Krypton::Start(const KryptonConfig& config) {
  LOG(INFO) << "Starting Krypton with zinc=" << config.zinc_url()
            << " brass=" << config.brass_url()
            << " service_type=" << config.service_type()
            << " safe_disconnect_enabled=" << config.safe_disconnect_enabled();

  config_ = config;
  notification_thread_ =
      std::make_unique<utils::LooperThread>("Krypton Looper");
  session_manager_ = std::make_unique<SessionManager>(
      config_, http_fetcher_, timer_manager_, vpn_service_, oauth_,
      notification_thread_.get());
  tunnel_manager_ = std::make_unique<TunnelManager>(
      vpn_service_, config.safe_disconnect_enabled());
  clock_ = std::make_unique<RealClock>();
  reconnector_ = std::make_unique<Reconnector>(
      timer_manager_, config, session_manager_.get(), tunnel_manager_.get(),
      notification_thread_.get(), clock_.get());
  reconnector_->RegisterNotificationInterface(notification_);

  notification_thread_->Post([this] { Init(); });

  {
    absl::MutexLock l(&stopped_lock_);
    stopped_ = false;
  }
}

Krypton::~Krypton() {
  absl::MutexLock l(&stopped_lock_);
  if (!stopped_) {
    LOG(DFATAL) << "Please call |Stop| before deleting this object";
  }
}

void Krypton::Stop(const absl::Status& status) {
  LOG(INFO) << "Stopping Krypton with status: " << status;
  if (reconnector_ != nullptr) {
    reconnector_->Stop();
  }

  if (tunnel_manager_ != nullptr) {
    tunnel_manager_->Stop();
  }

  {
    absl::MutexLock l(&stopped_lock_);
    if (stopped_) {
      LOG(WARNING) << "|Stop| was called when Krypton was already stopped.";
      return;
    }
  }

  if (notification_thread_ == nullptr) {
    LOG(WARNING) << "notification_thread_ was NULL for running Krypton.";
    return;
  }

  auto thread = std::move(notification_thread_);
  thread->Stop();
  thread->Join();

  {
    absl::MutexLock l(&stopped_lock_);
    stopped_ = true;
    stopped_condition_.SignalAll();
  }
}

void Krypton::Snooze(absl::Duration duration) {
  LOG(INFO) << "Snoozing krypton.";

  auto status = reconnector_->Snooze(duration);
  if (status.ok()) {
    LOG(INFO) << "Snoozed krypton for " << duration;
  } else {
    LOG(ERROR) << "Failed to snooze krypton: " << status;
  }
}

void Krypton::Resume() {
  LOG(INFO) << "Resuming krypton.";
  auto status = reconnector_->Resume();
  if (status.ok()) {
    LOG(INFO) << "Krypton resumed.";
  } else {
    LOG(ERROR) << "Krypton failed to resume: " << status;
  }
}

void Krypton::ExtendSnooze(absl::Duration extendDuration) {
  LOG(INFO) << "Extending snoozing krypton.";

  auto status = reconnector_->ExtendSnooze(extendDuration);
  if (status.ok()) {
    LOG(INFO) << "Krypton snoozed for additional " << extendDuration;
  } else {
    LOG(ERROR) << "Failed to extend krypton snooze";
  }
}

void Krypton::WaitForTermination() {
  absl::MutexLock l(&stopped_lock_);
  while (!stopped_) {
    stopped_condition_.Wait(&stopped_lock_);
  }
}

void Krypton::Init() {
  LOG(INFO) << "Started Initialization";

  auto status = tunnel_manager_->Start();
  if (!status.ok()) {
    reconnector_->PermanentFailure(status);
    return;
  }
  reconnector_->Start();

  LOG(INFO) << "Initialization done";
}

absl::Status Krypton::SetNetwork(const NetworkInfo& network_info) {
  return reconnector_->SetNetwork(network_info);
}

absl::Status Krypton::SetNoNetworkAvailable() {
  return reconnector_->SetNetwork(std::nullopt);
}

void Krypton::SetSafeDisconnectEnabled(bool enable) {
  tunnel_manager_->SetSafeDisconnectEnabled(enable);
}

bool Krypton::IsSafeDisconnectEnabled() {
  return tunnel_manager_->IsSafeDisconnectEnabled();
}

void Krypton::SetSimulatedNetworkFailure(bool simulated_network_failure) {
  reconnector_->SetSimulatedNetworkFailure(simulated_network_failure);
}

void Krypton::CollectTelemetry(KryptonTelemetry* telemetry) {
  if (session_manager_ != nullptr) {
    session_manager_->CollectTelemetry(telemetry);
  }
  if (reconnector_ != nullptr) {
    reconnector_->CollectTelemetry(telemetry);
  }
}

void Krypton::GetDebugInfo(KryptonDebugInfo* debug_info) {
  *debug_info->mutable_config() = config_;

  if (session_manager_ != nullptr) {
    session_manager_->GetDebugInfo(debug_info);
  }
  if (reconnector_ != nullptr) {
    reconnector_->GetDebugInfo(debug_info->mutable_reconnector());
  }
}

}  // namespace krypton
}  // namespace privacy
