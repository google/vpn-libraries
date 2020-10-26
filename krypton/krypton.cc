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

#include "privacy/net/krypton/krypton.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/session_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/memory/memory.h"
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
            << " service_type=" << config.service_type();

  if (config.install_crash_signal_handler()) {
    LOG(INFO) << "Installing Krypton crash signal handler.";
    SignalHandler::RegisterNotificationInterface(notification_);
  }

  config_ = config;
  notification_thread_ =
      std::make_unique<utils::LooperThread>("Krypton Looper");
  session_manager_ = absl::make_unique<SessionManager>(
      http_fetcher_, timer_manager_, vpn_service_, oauth_, &config_,
      notification_thread_.get());
  reconnector_ = absl::make_unique<Reconnector>(timer_manager_, config,
                                                session_manager_.get(),
                                                notification_thread_.get());
  reconnector_->RegisterNotificationInterface(notification_);

  notification_thread_->Post([this] { Init(); });

  {
    absl::MutexLock l(&stopped_lock_);
    stopped_ = false;
  }
}

Krypton::~Krypton() {
  SignalHandler::RegisterNotificationInterface(nullptr);

  absl::MutexLock l(&stopped_lock_);
  if (!stopped_) {
    LOG(DFATAL) << "Please call |Stop| before deleting this object";
  }
}

void Krypton::Stop(const absl::Status& status) {
  if (reconnector_ != nullptr) {
    reconnector_->Stop();
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

void Krypton::WaitForTermination() {
  absl::MutexLock l(&stopped_lock_);
  while (!stopped_) {
    stopped_condition_.Wait(&stopped_lock_);
  }
}

void Krypton::Init() {
  LOG(INFO) << "Started Initialization";

  reconnector_->Start();

  LOG(INFO) << "Initialization done";
}

absl::Status Krypton::SetNetwork(const NetworkInfo& network_info) {
  int network_fd = network_info.protected_fd();
  NetworkType network_type = network_info.network_type();

  LOG(INFO) << "Switching to network with fd=" << network_fd
            << ", type=" << network_type;
  if (network_type < 0 || network_type > privacy::krypton::NetworkType_MAX) {
    return absl::OutOfRangeError(
        absl::StrCat("Invalid network type ", network_type));
  }
  if (network_type == NetworkType::UNKNOWN_TYPE) {
    return absl::InvalidArgumentError("Unknown network type in setNetwork");
  }

  return reconnector_->SetNetwork(network_info);
}

absl::Status Krypton::SetNoNetworkAvailable() {
  return reconnector_->SetNetwork(absl::nullopt);
}

absl::Status Krypton::Pause(absl::Duration duration) {
  return reconnector_->Pause(duration);
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
