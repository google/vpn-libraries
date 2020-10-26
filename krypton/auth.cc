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

#include "privacy/net/krypton/auth.h"

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/auth_and_sign_request.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

const uint32 kLatencyCollectionLimit = 5;

std::string StateString(Auth::State state) {
  switch (state) {
    case Auth::State::kAuthenticated:
      return "Authenticated";
    case Auth::State::kUnauthenticated:
      return "Unauthenticated";
  }
}

}  // namespace
Auth::Auth(KryptonConfig* config, HttpFetcherInterface* http_fetcher_native,
           OAuthInterface* oath_native, utils::LooperThread* looper_thread)
    : state_(State::kUnauthenticated),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher_native),
                    ABSL_DIE_IF_NULL(looper_thread)),
      oauth_(ABSL_DIE_IF_NULL(oath_native)),
      looper_thread_(looper_thread),
      config_(ABSL_DIE_IF_NULL(config)) {}

Auth::~Auth() {
  absl::MutexLock l(&mutex_);
  if (stopped_ == false) {
    LOG(DFATAL) << "Call Stop before exiting Auth";
  }
}

void Auth::HandleAuthAndSignResponse(bool is_rekey,
                                     const std::string& string_response) {
  absl::MutexLock l(&mutex_);
  google::protobuf::Duration latency;
  if (!utils::ToProtoDuration(absl::Now() - request_time_, &latency).ok()) {
    LOG(ERROR) << "Unable to calculate latency.";
  } else {
    if (latencies_.size() < kLatencyCollectionLimit) {
      latencies_.emplace_back(latency);
    } else {
      LOG(ERROR) << "Max latency collection limit reached, not adding latency:"
                 << absl::Now() - request_time_;
    }
  }

  request_time_ = ::absl::InfinitePast();

  LOG(INFO) << "Got Authentication Response. Rekey:"
            << (is_rekey ? "True" : "False");

  if (stopped_) {
    LOG(ERROR) << "Auth is already cancelled, don't update";
    return;
  }

  auto auth_and_sign_response = std::make_shared<AuthAndSignResponse>();

  auto decode_status =
      auth_and_sign_response->DecodeFromJsonObject(string_response);
  auth_and_sign_response_ = std::move(auth_and_sign_response);

  if (!decode_status.ok()) {
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification();
    LOG(ERROR) << "Error decoding AuthResponse " << string_response;
    return;
  }
  if (!auth_and_sign_response_->http_response().is_successful()) {
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification();
    return;
  }
  SetState(State::kAuthenticated);
  auto* notification = notification_;
  looper_thread_->Post(
      [notification, is_rekey] { notification->AuthSuccessful(is_rekey); });
  LOG(INFO) << "Exiting authentication response";
}

std::shared_ptr<AuthAndSignResponse> Auth::auth_response() const {
  absl::MutexLock l(&mutex_);
  return auth_and_sign_response_;
}

void Auth::HandlePublicKeyResponse(bool is_rekey,
                                   const std::string& string_response) {
  {
    absl::MutexLock l(&mutex_);
    google::protobuf::Duration latency;
    const auto latency_status =
        utils::ToProtoDuration(absl::Now() - request_time_, &latency);
    if (!latency_status.ok()) {
      LOG(ERROR) << "Unable to calculate latency with status:"
                 << latency_status;
    } else {
      latencies_.emplace_back(latency);
    }

    request_time_ = ::absl::InfinitePast();

    LOG(INFO) << "Got PublicKeyResponse Response.";

    if (stopped_) {
      LOG(ERROR) << "Auth is already cancelled, don't update";
      return;
    }

    PublicKeyResponse response;
    if (const auto decode_status =
            response.DecodeFromJsonObject(string_response);
        !decode_status.ok()) {
      latest_status_ = decode_status;
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification();
      LOG(ERROR) << "Error decoding PublicKeyResponse " << string_response;
      return;
    }
    DCHECK_NE(key_material_, nullptr);
    auto blinding_status = key_material_->SetBlindingPublicKey(response.pem());
    if (!blinding_status.ok()) {
      latest_status_ = blinding_status;
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification();
      return;
    }
  }
  Authenticate(is_rekey);
  LOG(INFO) << "Exiting PublicKeyResponse";
}

absl::StatusOr<std::string> Auth::signer_public_key() const {
  absl::MutexLock l(&mutex_);
  if (signer_public_key_.empty()) {
    return absl::FailedPreconditionError("PEM is uninitialized");
  }
  return signer_public_key_;
}

void Auth::Start(bool is_rekey) {
  if (config_->enable_blind_signing()) {
    LOG(INFO) << "Starting authentication with blind signing. Rekey:"
              << (is_rekey ? "true" : "false");
    RequestKeyForBlindSigning(is_rekey);
  } else {
    LOG(INFO) << "Starting authentication without blind signing. Rekey:"
              << (is_rekey ? "true" : "false");
    Authenticate(is_rekey);
  }
}

void Auth::RequestKeyForBlindSigning(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  request_time_ = absl::Now();
  PublicKeyRequest request;
  auto public_key_json_object = request.EncodeToJsonObject();
  if (!public_key_json_object) {
    LOG(ERROR) << "Cannot build PublicKeyRequest";
    latest_status_ =
        absl::PermissionDeniedError("Cannot build PublicKeyRequest");
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification();
    return;
  }

  http_fetcher_.PostJsonAsync(
      config_->zinc_public_signing_key_url(),
      public_key_json_object.value().http_headers,
      public_key_json_object.value().json_body,
      absl::bind_front(&Auth::HandlePublicKeyResponse, this, is_rekey));
}

void Auth::Authenticate(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  request_time_ = absl::Now();
  auto status_or_auth_token = oauth_->GetOAuthToken();
  if (!status_or_auth_token.ok()) {
    LOG(ERROR) << "Error fetching oauth token";
    latest_status_ = absl::InternalError("Error fetching Oauth token");
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification();
    return;
  }
  auto auth_token = status_or_auth_token.value();
  AuthAndSignRequest sign_request(
      auth_token, config_->service_type(), std::string(),
      config_->enable_blind_signing() ? key_material_->GetZincBlindToken()
                                      : absl::nullopt,
      config_->enable_blind_signing()
          ? key_material_->blind_signing_public_key_hash()
          : absl::nullopt);

  auto auth_json_object = sign_request.EncodeToJsonObject();
  if (!auth_json_object) {
    LOG(ERROR) << "Cannot build AuthAndSignRequest";
    latest_status_ =
        absl::PermissionDeniedError("Cannot build AuthAndSignRequest");
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification();
    return;
  }

  http_fetcher_.PostJsonAsync(
      config_->zinc_url(), auth_json_object.value().http_headers,
      auth_json_object.value().json_body,
      absl::bind_front(&Auth::HandleAuthAndSignResponse, this, is_rekey));
}

void Auth::RaiseAuthFailureNotification() const {
  // If the status is set, send it else calculate the status.
  if (!latest_status_.ok()) {
    auto* notification = notification_;
    auto status = latest_status_;
    looper_thread_->Post(
        [notification, status] { notification->AuthFailure(status); });
    return;
  }

  if (auth_and_sign_response_ == nullptr) {
    absl::Status status(absl::StatusCode::kUnavailable,
                        "Authentication response is null");
    auto* notification = notification_;
    looper_thread_->Post(
        [notification, status] { notification->AuthFailure(status); });
    return;
  }

  // Build status from the HTTP response.
  absl::Status status(utils::GetStatusCodeForHttpStatus(
                          auth_and_sign_response_->http_response().status()),
                      auth_and_sign_response_->http_response().message());
  auto* notification = notification_;
  looper_thread_->Post(
      [notification, status] { notification->AuthFailure(status); });
}

void Auth::SetState(Auth::State state) {
  LOG(INFO) << "Transitioning from " << StateString(state_) << " to "
            << StateString(state);
  state_ = state;
}

Auth::State Auth::GetState() const {
  absl::MutexLock l(&mutex_);
  return state_;
}

void Auth::Stop() {
  // There should be a better way to cancel the thread as it has reference to
  // the Auth object and it might lead to crash if the response comes back.
  stopped_ = true;
  http_fetcher_.CancelAsync();
}

void Auth::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  for (const auto& latency : latencies_) {
    *telemetry->add_auth_latency() = latency;
  }
  latencies_.clear();
}

void Auth::GetDebugInfo(AuthDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  debug_info->set_state(StateString(state_));
  debug_info->set_status(latest_status_.ToString());
  for (const auto& latency : latencies_) {
    *debug_info->add_latency() = latency;
  }
}

}  // namespace krypton
}  // namespace privacy
