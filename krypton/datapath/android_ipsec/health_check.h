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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_HEALTH_CHECK_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_HEALTH_CHECK_H_

#include <atomic>
#include <memory>
#include <string>

#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Periodically performs a health check to verify that the device can still
// connect to the internet through the VPN.
// This class is thread-safe.
class HealthCheck {
 public:
  // Any class using HealthCheck should override this notification interface.
  // The functions here will be called when the periodic health check detects an
  // unhealthy state.
  class NotificationInterface {
   public:
    virtual ~NotificationInterface() = default;

    virtual void HealthCheckFailed(const absl::Status& status) = 0;
  };

  HealthCheck(const KryptonConfig& config, TimerManager* timer_manager,
              NotificationInterface* notification,
              utils::LooperThread* notification_thread);

  ~HealthCheck();

  // Starts the timer for the health check. The health check will continue until
  // a failure occurs or Stop is called.
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  // Stop will cancel the current health check. Calling Start after Stop will
  // restart the health check.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  void ConfigureHealthCheck(const KryptonConfig& config)
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status CheckConnection() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void StartHealthCheckTimer(bool prev_timer_expired)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void CancelHealthCheckTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void HandleHealthCheckTimeout(std::shared_ptr<std::atomic_bool> cancelled);

  absl::Mutex mutex_;

  TimerManager* timer_manager_;               // Not owned.
  NotificationInterface* notification_;       // Not owned.
  utils::LooperThread* notification_thread_;  // Not owned.

  utils::LooperThread looper_{"HealthCheck Looper"};
  bool periodic_health_check_enabled_ ABSL_GUARDED_BY(mutex_);
  absl::Duration periodic_health_check_duration_ ABSL_GUARDED_BY(mutex_);
  std::string periodic_health_check_url_ ABSL_GUARDED_BY(mutex_);
  uint32_t periodic_health_check_port_ ABSL_GUARDED_BY(mutex_);
  int health_check_timer_id_ ABSL_GUARDED_BY(mutex_);
  std::shared_ptr<std::atomic_bool> health_check_cancelled_
      ABSL_GUARDED_BY(mutex_);
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_HEALTH_CHECK_H_
