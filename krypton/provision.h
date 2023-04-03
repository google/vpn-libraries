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

#ifndef PRIVACY_NET_KRYPTON_PROVISION_H_
#define PRIVACY_NET_KRYPTON_PROVISION_H_

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

// Handles provisioning an egress through Auth and EgressManager.
// This is the parts of Session that are not related to the datapath.
class Provision : public Auth::NotificationInterface,
                  public EgressManager::NotificationInterface {
 public:
  // Notification for Session state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    virtual void Provisioned(const AddEgressResponse& egress_response,
                             bool is_rekey) = 0;
    virtual void ProvisioningFailure(absl::Status status, bool permanent) = 0;
  };

  Provision(const KryptonConfig& config, Auth* auth,
            EgressManager* egress_manager, HttpFetcherInterface* http_fetcher,
            utils::LooperThread* notification_thread);

  ~Provision() override = default;

  // Register for status change notifications.
  void RegisterNotificationHandler(NotificationInterface* notification) {
    notification_ = notification;
  }

  // Starts provisioning.
  void Start() ABSL_LOCKS_EXCLUDED(mutex_);

  absl::Status Rekey() ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<TransformParams> GetTransformParams()
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Override methods from the interface.
  void AuthSuccessful(bool is_rekey) override ABSL_LOCKS_EXCLUDED(mutex_);
  void AuthFailure(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void EgressAvailable(bool is_rekey) override ABSL_LOCKS_EXCLUDED(mutex_);
  void EgressUnavailable(const absl::Status& status) override
      ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  void FailWithStatus(absl::Status status, bool permanent);

  absl::Status SetRemoteKeyMaterial(const AddEgressResponse& egress)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void PpnDataplaneRequest(bool rekey = false)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  mutable absl::Mutex mutex_;

  KryptonConfig config_;

  Auth* auth_;                           // Not owned.
  EgressManager* egress_manager_;        // Not owned.
  NotificationInterface* notification_;  // Not owned.
  HttpFetcher http_fetcher_;
  utils::LooperThread* notification_thread_;  // Not owned.

  std::unique_ptr<crypto::SessionCrypto> key_material_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PROVISION_H_
