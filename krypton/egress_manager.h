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

#ifndef PRIVACY_NET_KRYPTON_EGRESS_MANAGER_H_
#define PRIVACY_NET_KRYPTON_EGRESS_MANAGER_H_

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

class EgressDebugInfo;

// API for key management or Exit nodes.  This class manages all the egress node
// details.
// Thread safe.
class EgressManager {
 public:
  // Notification for Egress Manager state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Notification on the status of Egress session establishment.
    virtual void EgressAvailable(bool is_rekey) = 0;
    virtual void EgressUnavailable(const absl::Status& status) = 0;
  };
  enum class State {
    kInitialized,
    kEgressSessionCreated,
    kEgressSessionError,
  };

  EgressManager(const KryptonConfig& config,
                HttpFetcherInterface* http_fetcher);
  virtual ~EgressManager();

  // Gets the egress node details for PPN using IPSec
  absl::Status GetEgressNodeForPpnIpSec(
      const AddEgressRequest::PpnDataplaneRequestParams& params)
      ABSL_LOCKS_EXCLUDED(mutex_);
  // Egress node details.
  absl::StatusOr<AddEgressResponse> GetEgressSessionDetails() const
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Stop the processing of the Egress response for any inflight requests.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  State GetState() const ABSL_LOCKS_EXCLUDED(mutex_) {
    absl::MutexLock l(&mutex_);
    return state_;
  }

  // Update the notification where the events are generated to.
  void RegisterNotificationHandler(NotificationInterface* notification,
                                   utils::LooperThread* notification_thread) {
    notification_ = notification;
    notification_thread_ = notification_thread;
  }

  void CollectTelemetry(KryptonTelemetry* telemetry)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void GetDebugInfo(EgressDebugInfo* debug_info) ABSL_LOCKS_EXCLUDED(mutex_);

  uint32_t uplink_spi() const {
    absl::MutexLock l(&mutex_);
    return uplink_spi_;
  }

 private:
  void DecodeAddEgressResponse(bool is_rekey, const HttpResponse& http_response)
      ABSL_LOCKS_EXCLUDED(mutex_);
  void SetState(State state) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  absl::Status SaveEgressDetails(const AddEgressResponse& egress_response)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  mutable absl::Mutex mutex_;
  std::optional<AddEgressResponse> egress_node_response_
      ABSL_GUARDED_BY(mutex_);

  KryptonConfig config_;
  utils::LooperThread looper_;
  HttpFetcher http_fetcher_;
  NotificationInterface* notification_;       // Not owned.
  utils::LooperThread* notification_thread_;  // Not owned.

  std::atomic_bool stopped_ ABSL_GUARDED_BY(mutex_) = false;
  const std::string brass_url_ ABSL_GUARDED_BY(mutex_);
  State state_ ABSL_GUARDED_BY(mutex_);
  absl::Status latest_status_ ABSL_GUARDED_BY(mutex_) = absl::OkStatus();
  uint32_t uplink_spi_ ABSL_GUARDED_BY(mutex_) = -1;
  std::vector<google::protobuf::Duration> latencies_ ABSL_GUARDED_BY(mutex_);
  absl::Time request_time_ ABSL_GUARDED_BY(mutex_) = absl::InfinitePast();
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_EGRESS_MANAGER_H_
