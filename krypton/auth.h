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

#ifndef PRIVACY_NET_KRYPTON_AUTH_H_
#define PRIVACY_NET_KRYPTON_AUTH_H_

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/call_once.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

class AuthDebugInfo;

// Thread Safe implementation of PPN Authentication.
// All the methods provide a non blocking interface but the caller can know the
// status by subscribing to the NotificationInterface.
class Auth {
 public:
  // Notification for Auth state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Changes to Authentication state.
    virtual void AuthSuccessful(bool is_rekey) = 0;
    // Temporary and permanent auth failures.
    virtual void AuthFailure(const absl::Status& status) = 0;
  };
  enum class State {
    kAuthenticated,   // User is authenticated
    kUnauthenticated  // User is not authenticated.
  };

  Auth(const KryptonConfig& config, HttpFetcherInterface* http_fetcher_native,
       OAuthInterface* oath_native, utils::LooperThread* looper_thread_);
  virtual ~Auth();

  // Register for auth status change notifications.
  void RegisterNotificationHandler(Auth::NotificationInterface* notification) {
    notification_ = notification;
  }

  void SetCrypto(crypto::SessionCrypto* key_material) {
    key_material_ = key_material;
  }

  // State of the current authentication.  If the status need to be async, use
  // notification handler.
  State GetState() const ABSL_LOCKS_EXCLUDED(mutex_);

  // Entry point to start the authentication procedures. |NotificationInterface|
  // will be called on successful or unsuccessful authentication.
  // Same API is used for starting Rekey procedures.
  virtual void Start(bool is_rekey) ABSL_LOCKS_EXCLUDED(mutex_);

  // Stop needs to be called to exit the underlying threads clean.
  void Stop() ABSL_LOCKS_EXCLUDED(mutex_);

  virtual AuthAndSignResponse auth_response() const ABSL_LOCKS_EXCLUDED(mutex_);

  void CollectTelemetry(KryptonTelemetry* telemetry)
      ABSL_LOCKS_EXCLUDED(mutex_);

  void GetDebugInfo(AuthDebugInfo* debug_info) ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<std::string> signer_public_key() const
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<std::string> fetch_nonce() const ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  void RequestKeyForBlindSigning(bool is_rekey) ABSL_LOCKS_EXCLUDED(mutex_);

  // Authenticates with Auth server and is a non blocking call.
  void Authenticate(bool is_rekey, std::optional<std::string> nonce)
      ABSL_LOCKS_EXCLUDED(mutex_);

  // Sets the authentication sate.
  void SetState(State) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void HandleAuthAndSignResponse(bool is_rekey, const HttpResponse& response)
      ABSL_LOCKS_EXCLUDED(mutex_);
  void HandlePublicKeyResponse(bool is_rekey, const HttpResponse& http_response)
      ABSL_LOCKS_EXCLUDED(mutex_);
  static void RecordLatency(absl::Time start,
                            std::vector<google::protobuf::Duration>* latencies,
                            const std::string& latency_type);

  State state_ ABSL_GUARDED_BY(mutex_);
  mutable absl::Mutex mutex_;
  AuthAndSignResponse auth_and_sign_response_ ABSL_GUARDED_BY(mutex_);

  void RaiseAuthFailureNotification(absl::Status status)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  std::string FetchAttestationDataWithNonce(const std::string& nonce)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  HttpFetcher http_fetcher_;
  KryptonConfig config_;

  OAuthInterface* oauth_;                // Not owned.
  NotificationInterface* notification_;  // Not owned.
  utils::LooperThread* looper_thread_;   // Not owned.
  crypto::SessionCrypto* key_material_;  // Not owned.

  std::atomic_bool stopped_ = false;
  absl::Status latest_status_ ABSL_GUARDED_BY(mutex_) = absl::OkStatus();
  std::vector<google::protobuf::Duration> latencies_ ABSL_GUARDED_BY(mutex_);
  std::vector<google::protobuf::Duration> oauth_latencies_
      ABSL_GUARDED_BY(mutex_);
  std::vector<google::protobuf::Duration> zinc_latencies_
      ABSL_GUARDED_BY(mutex_);
  absl::Time request_time_ ABSL_GUARDED_BY(mutex_) = ::absl::InfinitePast();
  absl::Time zinc_call_time_ ABSL_GUARDED_BY(mutex_) = ::absl::InfinitePast();
  std::string signer_public_key_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_AUTH_H_
