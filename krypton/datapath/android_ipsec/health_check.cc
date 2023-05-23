// Copyright 2023 Google LLC
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

#include "privacy/net/krypton/datapath/android_ipsec/health_check.h"

#include <atomic>
#include <cstring>
#include <memory>

#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/log/log.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {
constexpr int kInvalidTimerId = -1;
}

HealthCheck::HealthCheck(const KryptonConfig& config,
                         TimerManager* timer_manager,
                         NotificationInterface* notification,
                         utils::LooperThread* notification_thread)
    : timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      notification_(ABSL_DIE_IF_NULL(notification)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)),
      periodic_health_check_enabled_(false),
      health_check_timer_id_(kInvalidTimerId),
      health_check_cancelled_(nullptr) {
  ConfigureHealthCheck(config);
}

HealthCheck::~HealthCheck() { Stop(); }

void HealthCheck::Start() {
  absl::MutexLock lock(&mutex_);
  LOG(INFO) << "Health check start called.";
  if (!periodic_health_check_enabled_) {
    LOG(INFO) << "Health check disabled.";
    return;
  }
  StartHealthCheckTimer(/*prev_timer_expired=*/false);
}

void HealthCheck::Stop() {
  absl::MutexLock lock(&mutex_);
  LOG(INFO) << "Health check stop called.";
  CancelHealthCheckTimer();
}

void HealthCheck::ConfigureHealthCheck(const KryptonConfig& config) {
  absl::MutexLock lock(&mutex_);
  if (config.periodic_health_check_enabled()) {
    if (!config.has_periodic_health_check_duration()) {
      LOG(ERROR) << "Unable to enable health check without a duration.";
      return;
    }
    if (config.periodic_health_check_url().empty()) {
      LOG(ERROR) << "Unable to enable health check without a url.";
      return;
    }
    if (!config.has_periodic_health_check_port()) {
      LOG(ERROR) << "Unable to enable health check without a port.";
      return;
    }

    auto periodic_health_check_duration =
        utils::DurationFromProto(config.periodic_health_check_duration());
    if (!periodic_health_check_duration.ok()) {
      LOG(ERROR) << "Failed to convert health check duration: "
                 << periodic_health_check_duration.status();
      return;
    }

    periodic_health_check_url_ = config.periodic_health_check_url();
    periodic_health_check_port_ = config.periodic_health_check_port();
    periodic_health_check_duration_ = *periodic_health_check_duration;
    periodic_health_check_enabled_ = true;

    LOG(INFO) << "Health check configured with url: "
              << periodic_health_check_url_
              << ", port: " << periodic_health_check_port_ << ", and duration "
              << periodic_health_check_duration_;
  }
}

absl::Status HealthCheck::CheckConnection() const {
  PPN_ASSIGN_OR_RETURN(auto resolved_address,
                       utils::ResolveIPAddress(periodic_health_check_url_));
  PPN_ASSIGN_OR_RETURN(auto ip_range, utils::IPRange::Parse(resolved_address));
  sockaddr_storage addr;
  socklen_t addr_len;
  PPN_RETURN_IF_ERROR(
      ip_range.GenericAddress(periodic_health_check_port_, &addr, &addr_len));

  int sockfd = socket(addr.ss_family, SOCK_STREAM, 0);
  if (sockfd < 0) {
    return absl::InternalError(absl::StrCat(
        "Failed to create socket for health check: ", strerror(errno)));
  }
  absl::Cleanup close_sock = [sockfd] { close(sockfd); };

  int result = connect(sockfd, reinterpret_cast<sockaddr*>(&addr), addr_len);
  if (result < 0) {
    return absl::InternalError(absl::StrCat(
        "Failed to connect to endpoint for health check: ", strerror(errno)));
  }

  return absl::OkStatus();
}

void HealthCheck::StartHealthCheckTimer(bool prev_timer_expired) {
  if (!prev_timer_expired) {
    CancelHealthCheckTimer();
  }
  health_check_cancelled_ = std::make_shared<std::atomic_bool>(false);
  LOG(INFO) << "Starting HealthCheck timer.";
  auto timer_id = timer_manager_->StartTimer(
      periodic_health_check_duration_,
      absl::bind_front(&HealthCheck::HandleHealthCheckTimeout, this,
                       health_check_cancelled_));
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for HealthCheck";
    return;
  }
  health_check_timer_id_ = *timer_id;
  LOG(INFO) << "Started HealthCheck timer with id: " << health_check_timer_id_;
}

void HealthCheck::CancelHealthCheckTimer() {
  if (health_check_cancelled_ != nullptr) {
    LOG(INFO) << "Marking health check timer as cancelled.";
    *health_check_cancelled_ = true;
    health_check_cancelled_.reset();
  }
  if (health_check_timer_id_ != kInvalidTimerId) {
    LOG(INFO) << " Cancelling HealthCheck timer with id: "
              << health_check_timer_id_;
    timer_manager_->CancelTimer(health_check_timer_id_);
    health_check_timer_id_ = kInvalidTimerId;
  }
}

void HealthCheck::HandleHealthCheckTimeout(
    std::shared_ptr<std::atomic_bool> cancelled) {
  looper_.Post([cancelled, this]() {
    absl::MutexLock lock(&mutex_);
    LOG(INFO) << "Starting HealthCheck.";
    if (*cancelled) {
      LOG(INFO) << "HealthCheck timeout occurred after it was cancelled.";
      return;
    }
    auto status = CheckConnection();
    LOG(INFO) << "HealthCheck finished with status: " << status;
    if (!status.ok()) {
      auto* notification = notification_;
      notification_thread_->Post([notification, status]() {
        notification->HealthCheckFailed(status);
      });
      return;
    }
    StartHealthCheckTimer(/*prev_timer_expired=*/true);
  });
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
