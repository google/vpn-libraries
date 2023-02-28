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

#include "privacy/net/krypton/auth.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/auth_and_sign_request.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/functional/bind_front.h"
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

const uint32_t kLatencyCollectionLimit = 5;

std::string StateString(Auth::State state) {
  switch (state) {
    case Auth::State::kAuthenticated:
      return "Authenticated";
    case Auth::State::kUnauthenticated:
      return "Unauthenticated";
  }
}

}  // namespace
Auth::Auth(const KryptonConfig& config,
           HttpFetcherInterface* http_fetcher_native,
           OAuthInterface* oath_native, utils::LooperThread* looper_thread)
    : state_(State::kUnauthenticated),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher_native),
                    ABSL_DIE_IF_NULL(looper_thread)),
      config_(config),
      oauth_(ABSL_DIE_IF_NULL(oath_native)),
      looper_thread_(looper_thread) {}

Auth::~Auth() {
  absl::MutexLock l(&mutex_);
  if (stopped_ == false) {
    LOG(DFATAL) << "Call Stop before exiting Auth";
  }
}

void Auth::HandleAuthAndSignResponse(bool is_rekey,
                                     const HttpResponse& http_response) {
  absl::MutexLock l(&mutex_);
  RecordLatency(request_time_, &latencies_, "auth");
  RecordLatency(auth_call_time_, &zinc_latencies_, "zinc");

  request_time_ = ::absl::InfinitePast();

  LOG(INFO) << "Got Authentication Response. Rekey: "
            << (is_rekey ? "True" : "False")
            << ". Status: " << http_response.status().code();

  if (stopped_) {
    LOG(ERROR) << "Auth is already cancelled. Ignoring response.";
    return;
  }

  if (http_response.status().code() != 200) {
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(utils::GetStatusForHttpStatus(
        http_response.status().code(), http_response.status().message()));
    return;
  }

  auto auth_and_sign_response =
      AuthAndSignResponse::FromProto(http_response, config_);

  if (!auth_and_sign_response.ok()) {
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(auth_and_sign_response.status());
    LOG(ERROR) << "Error decoding AuthResponse";
    return;
  }
  auth_and_sign_response_ = *auth_and_sign_response;

  SetState(State::kAuthenticated);
  auto* notification = notification_;
  looper_thread_->Post(
      [notification, is_rekey] { notification->AuthSuccessful(is_rekey); });
  LOG(INFO) << "Exiting authentication response";
}

AuthAndSignResponse Auth::auth_response() const {
  absl::MutexLock l(&mutex_);
  return auth_and_sign_response_;
}

ppn::GetInitialDataResponse Auth::initial_data_response() const {
  absl::MutexLock l(&mutex_);
  return get_initial_data_response_;
}

void Auth::HandlePublicKeyResponse(bool is_rekey,
                                   const HttpResponse& http_response) {
  std::optional<std::string> nonce = std::nullopt;
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

    if (http_response.status().code() < 200 ||
        http_response.status().code() >= 300) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(utils::GetStatusForHttpStatus(
          http_response.status().code(), http_response.status().message()));
      LOG(ERROR) << "PublicKeyResponse failed: "
                 << http_response.status().code();
      return;
    }

    PublicKeyResponse response;
    const auto decode_status = response.DecodeFromProto(http_response);
    if (!decode_status.ok()) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(decode_status);
      LOG(ERROR) << "Error decoding PublicKeyResponse";
      return;
    }

    DCHECK_NE(key_material_, nullptr);
    auto blinding_status = key_material_->SetBlindingPublicKey(response.pem());
    if (!blinding_status.ok()) {
      LOG(ERROR) << "Error setting blinding public key";
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(blinding_status);
      return;
    }
    nonce = response.nonce();
  }
  Authenticate(is_rekey, nonce);
  LOG(INFO) << "Exiting PublicKeyResponse";
}

void Auth::HandleInitialDataResponse(bool is_rekey,
                                     const HttpResponse& http_response) {
  std::optional<std::string> nonce = std::nullopt;
  {
    absl::MutexLock l(&mutex_);
    // TODO
    RecordLatency(request_time_, &latencies_, "auth");

    request_time_ = ::absl::InfinitePast();

    LOG(INFO) << "Received GetInitialData Response.";
    if (stopped_) {
      LOG(ERROR) << "Auth is already cancelled, don't update";
      return;
    }
    if (http_response.status().code() < 200 ||
        http_response.status().code() >= 300) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(utils::GetStatusForHttpStatus(
          http_response.status().code(), http_response.status().message()));
      LOG(ERROR) << "GetInitialDataResponse failed: "
                 << http_response.status().code();
      return;
    }

    auto decode_status = DecodeGetInitialDataResponse(http_response);
    if (!decode_status.ok()) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(decode_status.status());
    }
    get_initial_data_response_ = decode_status.value();

    auto rounded_expiry_timestamp = utils::VerifyTimestampIsRounded(
        get_initial_data_response_.public_metadata_info()
            .public_metadata()
            .expiration(),
        expiry_increments_);
    if (!rounded_expiry_timestamp.ok()) {
      SetState(State::kUnauthenticated);
      LOG(ERROR) << "HandleInitialDataResponse failed due to unrounded expiry "
                    "increment.";
      return;
    }
    if (get_initial_data_response_.public_metadata_info()
            .public_metadata()
            .service_type() != config_.service_type()) {
      SetState(State::kUnauthenticated);
      LOG(ERROR) << "HandleInitialDataResponse failed due to incorrect service "
                    "type in response.";
      return;
    }

    DCHECK_NE(key_material_, nullptr);
    auto blinding_status = key_material_->SetBlindingPublicKey(
        get_initial_data_response_.at_public_metadata_public_key()
            .serialized_public_key());
    if (!blinding_status.ok()) {
      LOG(ERROR)
          << "HandleInitialDataResponse: Error setting blinding public key";
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(blinding_status);
      return;
    }
    if (!get_initial_data_response_.attestation().attestation_nonce().empty()) {
      nonce = get_initial_data_response_.attestation().attestation_nonce();
    }
  }
  LOG(INFO) << "Exiting InitialDataResponseHandler";
  Authenticate(is_rekey, nonce);
}

absl::StatusOr<std::string> Auth::signer_public_key() const {
  absl::MutexLock l(&mutex_);
  if (signer_public_key_.empty()) {
    return absl::FailedPreconditionError("PEM is uninitialized");
  }
  return signer_public_key_;
}

void Auth::Start(bool is_rekey) {
  if (config_.enable_blind_signing()) {
    LOG(INFO) << "Starting authentication with blind signing. Rekey:"
              << (is_rekey ? "true" : "false");
    if (config_.public_metadata_enabled()) {
      LOG(INFO) << "Requesting key with public metadata enabled.";
      RequestForInitialData(is_rekey);
    } else {
      LOG(INFO) << "Requesting key without public metadata enabled.";
      RequestKeyForBlindSigning(is_rekey);
    }
  } else {
    LOG(INFO) << "Starting authentication without blind signing. Rekey:"
              << (is_rekey ? "true" : "false");
    Authenticate(is_rekey, /*nonce=*/std::nullopt);
  }
}

void Auth::RequestKeyForBlindSigning(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  request_time_ = absl::Now();
  auto api_key = config_.has_api_key()
                     ? std::optional<std::string>(config_.api_key())
                     : std::nullopt;
  PublicKeyRequest request(
      /*request_nonce*/ config_.integrity_attestation_enabled(), api_key);
  auto public_key_proto = request.EncodeToProto();
  public_key_proto.set_url(config_.zinc_public_signing_key_url());
  http_fetcher_.PostJsonAsync(
      public_key_proto,
      absl::bind_front(&Auth::HandlePublicKeyResponse, this, is_rekey));
}

void Auth::RequestForInitialData(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  request_time_ = absl::Now();

  auto auth_token = oauth_->GetOAuthToken();
  if (!auth_token.ok()) {
    LOG(ERROR) << "Error fetching oauth token: " << auth_token.status();
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(
        absl::InternalError("Error fetching Oauth token"));
    return;
  }
  RecordLatency(request_time_, &oauth_latencies_, "oauth");

  auto use_attestation = config_.integrity_attestation_enabled();
  auto service_type = config_.service_type();

  // TODO Temporariliy setting to granularity to country level
  // until resolved.
  ppn::GetInitialDataRequest::LocationGranularity granularity =
      ppn::GetInitialDataRequest::COUNTRY;

  InitialDataRequest request(use_attestation, service_type, granularity,
                             *auth_token);
  auto get_initial_data_proto = request.EncodeToProto();
  get_initial_data_proto.set_url(config_.initial_data_url());
  http_fetcher_.PostJsonAsync(
      get_initial_data_proto,
      absl::bind_front(&Auth::HandleInitialDataResponse, this, is_rekey));
}

void Auth::Authenticate(bool is_rekey, std::optional<std::string> nonce) {
  absl::MutexLock l(&mutex_);
  std::optional<privacy::ppn::AttestationData> attestation_data;
  if (nonce.has_value()) {
    auto data = oauth_->GetAttestationData(*nonce);
    if (!data.ok()) {
      LOG(ERROR) << "Error fetching attestation data";
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(
          absl::InternalError("Error fetching attestation data"));
      return;
    }
    attestation_data = data.value();
  }
  request_time_ = absl::Now();
  auto auth_token = oauth_->GetOAuthToken();
  if (!auth_token.ok()) {
    LOG(ERROR) << "Error fetching oauth token: " << auth_token.status();
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(
        absl::InternalError("Error fetching Oauth token"));
    return;
  }
  RecordLatency(request_time_, &oauth_latencies_, "oauth");
  AuthAndSignRequest sign_request(
      *auth_token, config_.service_type(), std::string(),
      config_.enable_blind_signing() ? key_material_->GetZincBlindToken()
                                     : std::nullopt,
      config_.enable_blind_signing()
          ? key_material_->blind_signing_public_key_hash()
          : std::nullopt,
      attestation_data, config_.attach_oauth_token_as_header());

  auto auth_http_request = sign_request.EncodeToProto();
  if (!auth_http_request) {
    LOG(ERROR) << "Cannot build AuthAndSignRequest";
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(
        absl::PermissionDeniedError("Cannot build AuthAndSignRequest"));
    return;
  }

  // TODO: Clean up name of zinc_url.
  auth_http_request->set_url(config_.zinc_url());
  auth_call_time_ = absl::Now();
  http_fetcher_.PostJsonAsync(
      auth_http_request.value(),
      absl::bind_front(&Auth::HandleAuthAndSignResponse, this, is_rekey));
}

void Auth::RaiseAuthFailureNotification(absl::Status status) {
  auto* notification = notification_;
  // Make a copy of the status to show in the debug info.
  latest_status_ = status;
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
  for (const auto& latency : oauth_latencies_) {
    *telemetry->add_oauth_latency() = latency;
  }
  for (const auto& latency : zinc_latencies_) {
    *telemetry->add_zinc_latency() = latency;
  }
  latencies_.clear();
  oauth_latencies_.clear();
  zinc_latencies_.clear();
}

void Auth::GetDebugInfo(AuthDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  debug_info->set_state(StateString(state_));
  debug_info->set_status(latest_status_.ToString());
  for (const auto& latency : latencies_) {
    *debug_info->add_latency() = latency;
  }
}

void Auth::RecordLatency(absl::Time start,
                         std::vector<google::protobuf::Duration>* latencies,
                         const std::string& latency_type) {
  google::protobuf::Duration latency;
  absl::Duration latency_durition = absl::Now() - start;
  auto latency_status = utils::ToProtoDuration(latency_durition, &latency);
  if (!latency_status.ok()) {
    LOG(ERROR) << "Unable to calculate " << latency_type
               << " latency with status:" << latency_status;
    return;
  }
  if (latencies->size() >= kLatencyCollectionLimit) {
    LOG(ERROR) << "Max " << latency_type
               << " latency collection limit reached, not adding latency:"
               << latency_durition;
    return;
  }
  latencies->emplace_back(latency);
}

}  // namespace krypton
}  // namespace privacy
