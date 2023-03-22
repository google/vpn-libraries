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

#ifndef PRIVACY_NET_KRYPTON_KRYPTON_H_
#define PRIVACY_NET_KRYPTON_KRYPTON_H_

#include <atomic>
#include <memory>
#include <string>

#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/krypton_notification_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/reconnector.h"
#include "privacy/net/krypton/session_manager.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {

// There can only be one instance of Krypton running.
// Krypton is the starting class for C++ library providing PPN functionality.
// As PPN is the library, Krypton provides the equivalent of the |main| method.
class Krypton {
 public:
  Krypton(HttpFetcherInterface* http_fetcher,
          KryptonNotificationInterface* notification,
          VpnServiceInterface* vpn_service, OAuthInterface* oauth,
          TimerManager* timer_manager)
      : http_fetcher_(http_fetcher),
        notification_(notification),
        vpn_service_(vpn_service),
        oauth_(oauth),
        timer_manager_(timer_manager),
        stopped_(true) {}

  ~Krypton();

  // Initializes Krypton library and starts it. This internally starts a
  // thread.  Use |Stop| to stop the library. Called from Java library.
  void Start(const KryptonConfig& config);

  // Stop the Krypton library.  To have a clean exit, |Stop| needs to be called.
  void Stop() { Stop(absl::OkStatus()); }

  // Snooze Krypton.
  void Snooze(absl::Duration duration);

  void Resume();

  void ExtendSnooze(absl::Duration extendDuration);

  // Utility method for caller to block till krypton exits. Please do not use
  // this for JNI.
  void WaitForTermination() ABSL_LOCKS_EXCLUDED(stopped_lock_);

  // Set network.
  absl::Status SetNetwork(const NetworkInfo& network_info);

  // No network is available.
  absl::Status SetNoNetworkAvailable();

  // Set state of the Safe Disconnect feature.
  void SetSafeDisconnectEnabled(bool enabled);

  // Returns state of the Safe Disconnect feature.
  bool IsSafeDisconnectEnabled();

  // Sets whether to use city-level IPs for IP-geolocation.
  void SetIpGeoLevel(ppn::IpGeoLevel level);

  // Returns whether to use city-level IPs for IP-geolocation.
  ppn::IpGeoLevel GetIpGeoLevel();

  // Puts Krypton into a horrible wedged state. For testing.
  void SetSimulatedNetworkFailure(bool simulated_network_failure);

  // Collects telemetry to determine how well Krypton is running.
  void CollectTelemetry(KryptonTelemetry* telemetry);

  // Gets useful info for debugging.
  void GetDebugInfo(KryptonDebugInfo* debug_info);

 private:
  // Blocking call.
  void Init();

  void Stop(const absl::Status& status) ABSL_LOCKS_EXCLUDED(stopped_lock_);

  HttpFetcherInterface* http_fetcher_;          // Not owned.
  KryptonNotificationInterface* notification_;  // Not owned.
  VpnServiceInterface* vpn_service_;            // Not owned.
  OAuthInterface* oauth_;                       // Not owned.
  TimerManager* timer_manager_;                 // Not owned.

  std::unique_ptr<TunnelManager> tunnel_manager_;
  std::unique_ptr<SessionManager> session_manager_;
  std::unique_ptr<Reconnector> reconnector_;
  std::unique_ptr<utils::LooperThread> notification_thread_;
  std::unique_ptr<KryptonClock> clock_;

  bool stopped_ ABSL_GUARDED_BY(stopped_lock_);
  absl::Mutex stopped_lock_;
  absl::CondVar stopped_condition_ ABSL_GUARDED_BY(stopped_lock_);

  KryptonConfig config_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_KRYPTON_H_
