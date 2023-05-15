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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/cpp/public_metadata/fingerprint.h"
#include "privacy/net/common/cpp/public_metadata/serialize.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/key_services.proto.h"
#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/auth_and_sign_request.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/auth_crypto.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/log/die_if_null.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/anonymous_tokens/cpp/client/anonymous_tokens_rsa_bssa_client.h"
#include "third_party/anonymous_tokens/proto/anonymous_tokens.proto.h"

namespace privacy {
namespace krypton {
namespace {

const uint32_t kLatencyCollectionLimit = 5;
// Specify public metadata rules that must be matched by GetInitialDataResponse.
const int64_t kValidationVersion = 1;

std::string StateString(Auth::State state) {
  switch (state) {
    case Auth::State::kAuthenticated:
      return "Authenticated";
    case Auth::State::kUnauthenticated:
      return "Unauthenticated";
  }
}

ppn::GetInitialDataRequest::LocationGranularity GetLocationGranularity(
    privacy::ppn::IpGeoLevel ip_geo_level) {
  switch (ip_geo_level) {
    case ppn::COUNTRY:
      return ppn::GetInitialDataRequest::COUNTRY;
    case ppn::CITY:
      return ppn::GetInitialDataRequest::CITY_GEOS;
    default:
      return ppn::GetInitialDataRequest::UNKNOWN;
  }
}

absl::Status VerifyPublicMetadata(const ppn::PublicMetadata& public_metadata,
                                  const KryptonConfig& config,
                                  absl::Duration expiry_increments) {
  auto expiry_timestamp_status = utils::VerifyTimestampIsRounded(
      public_metadata.expiration(), expiry_increments);
  if (!expiry_timestamp_status.ok()) {
    return absl::InternalError(
        "HandleInitialDataResponse failed due to unrounded expiry "
        "increment.");
  }
  if (config.ip_geo_level() != ppn::CITY &&
      !public_metadata.exit_location().city_geo_id().empty()) {
    return absl::InternalError(
        "Received city_geo_id when request specified other geo level.");
  }
  if (public_metadata.service_type() != config.service_type()) {
    return absl::InternalError(
        "HandleInitialDataResponse failed due to incorrect service type "
        "in response.");
  }
  if (public_metadata.debug_mode() !=
          ppn::PublicMetadata::UNSPECIFIED_DEBUG_MODE &&
      !config.debug_mode_allowed()) {
    return absl::InternalError(
        "HandleInitialDataResponse failed due to debug mode specified when not "
        "allowed. Must set debug_mode_allowed before specifying a debug mode.");
  }
  return absl::OkStatus();
}

}  // namespace

using ::private_membership::anonymous_tokens::AnonymousTokensRsaBssaClient;
using ::private_membership::anonymous_tokens::AnonymousTokensSignResponse;
using ::private_membership::anonymous_tokens::
    PlaintextMessageWithPublicMetadata;
using ::private_membership::anonymous_tokens::RSABlindSignatureTokenWithInput;

Auth::Auth(const KryptonConfig& config,
           HttpFetcherInterface* http_fetcher_native,
           OAuthInterface* oath_native, utils::LooperThread* looper_thread)
    : state_(State::kUnauthenticated),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher_native),
                    ABSL_DIE_IF_NULL(looper_thread)),
      config_(config),
      oauth_(ABSL_DIE_IF_NULL(oath_native)),
      looper_thread_(looper_thread) {
  key_material_ = std::make_unique<crypto::AuthCrypto>(config);
}

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
            << ". Status: " << http_response.status().code()
            << "; Message: " << http_response.status().message();

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

  bool enforce_copper_suffix = get_initial_data_response_.public_metadata_info()
                                .public_metadata()
                                .debug_mode() != ppn::PublicMetadata::DEBUG_ALL;

  auto auth_and_sign_response = AuthAndSignResponse::FromProto(
      http_response, config_, enforce_copper_suffix);

  if (!auth_and_sign_response.ok()) {
    SetState(State::kUnauthenticated);
    RaiseAuthFailureNotification(auth_and_sign_response.status());
    LOG(ERROR) << "Error decoding AuthResponse";
    return;
  }
  auth_and_sign_response_ = *auth_and_sign_response;
  if (config_.public_metadata_enabled()) {
    signed_tokens_ = UnblindATToken();
    if (!signed_tokens_.ok()) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(signed_tokens_.status());
      LOG(ERROR) << "Error Signing Anonymous Token";
      return;
    }
  }

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

    auto decoded_response = DecodeGetInitialDataResponse(http_response);
    if (!decoded_response.ok()) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(decoded_response.status());
      return;
    }

    auto public_metadata_status = VerifyPublicMetadata(
        decoded_response.value().public_metadata_info().public_metadata(),
        config_, expiry_increments_);
    if (!public_metadata_status.ok()) {
      SetState(State::kUnauthenticated);
      RaiseAuthFailureNotification(public_metadata_status);
      LOG(ERROR) << public_metadata_status.message();
      return;
    }

    // set verified response
    get_initial_data_response_ = decoded_response.value();

    // Create RSA BSSA client.
    auto bssa_client = AnonymousTokensRsaBssaClient::Create(
        get_initial_data_response_.at_public_metadata_public_key());
    if (!bssa_client.ok()) {
      SetState(State::kUnauthenticated);
      LOG(ERROR)
          << "HandleInitialDataResponse Failed to create AT BSSA client: "
          << bssa_client.status();

      return;
    }
    // Create plaintext tokens.
    // Client blinds plaintext tokens (random 32-byte strings) in CreateRequest.
    std::vector<PlaintextMessageWithPublicMetadata> plaintext_tokens;
    PlaintextMessageWithPublicMetadata plaintext_message;
    //  Get random UTF8 32 byte string prefixed with "blind:".
    plaintext_message.set_plaintext_message(key_material_->original_message());
    uint64_t fingerprint = 0;
    absl::Status fingerprint_status = FingerprintPublicMetadata(
        get_initial_data_response_.public_metadata_info().public_metadata(),
        &fingerprint);
    if (!fingerprint_status.ok()) {
      SetState(State::kUnauthenticated);
      LOG(ERROR) << "Failed to fingerprint public metadata: "
                 << fingerprint_status;
      return;
    }

    plaintext_message.set_public_metadata(ppn::Uint64ToBytes(fingerprint));
    plaintext_tokens.push_back(plaintext_message);

    auto at_sign_request = bssa_client.value()->CreateRequest(plaintext_tokens);
    if (!at_sign_request.ok()) {
      SetState(State::kUnauthenticated);
      LOG(ERROR)
          << "HandleInitialDataResponse Failed to create AT Sign Request: "
          << at_sign_request.status();
      return;
    }
    bssa_client_ = *std::move(bssa_client);
    at_sign_request_ = at_sign_request.value();
    if (!get_initial_data_response_.attestation().attestation_nonce().empty()) {
      nonce = absl::Base64Escape(
          get_initial_data_response_.attestation().attestation_nonce());
    }
  }
  LOG(INFO) << "HandleInitialDataResponse Exiting InitialDataResponseHandler";

  AuthenticatePublicMetadata(is_rekey, nonce);
}

void Auth::Start(bool is_rekey) {
  {
    absl::MutexLock l(&mutex_);
    key_material_ = std::make_unique<crypto::AuthCrypto>(config_);
  }

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

std::string Auth::GetOriginalMessage() const {
  absl::MutexLock l(&mutex_);
  return key_material_->original_message();
}

std::optional<std::string> Auth::GetBrassUnblindedToken(
    absl::string_view zinc_blind_signature) const {
  absl::MutexLock l(&mutex_);
  return key_material_->GetBrassUnblindedToken(zinc_blind_signature);
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
  auto granularity = GetLocationGranularity(config_.ip_geo_level());

  InitialDataRequest request(use_attestation, service_type, granularity,
                             kValidationVersion, *auth_token);
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

void Auth::AuthenticatePublicMetadata(bool is_rekey,
                                      std::optional<std::string> nonce) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Entering AuthenticatePublicMetadata.";
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

  // Create AuthAndSign RPC.
  privacy::ppn::PublicMetadataInfo public_metadata_info =
      get_initial_data_response_.public_metadata_info();

  privacy::ppn::AuthAndSignRequest sign_request;
  sign_request.set_oauth_token(auth_token.value());
  sign_request.set_service_type(
      public_metadata_info.public_metadata().service_type());
  sign_request.set_key_type(privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE);
  sign_request.set_key_version(
      get_initial_data_response_.at_public_metadata_public_key().key_version());
  *sign_request.mutable_public_metadata_info() = public_metadata_info;
  for (int i = 0; i < at_sign_request_.blinded_tokens_size(); i++) {
    sign_request.add_blinded_token(absl::Base64Escape(
        at_sign_request_.blinded_tokens().at(i).serialized_token()));
  }

  HttpRequest auth_http_request;
  auth_http_request.set_proto_body(sign_request.SerializeAsString());
  if (config_.attach_oauth_token_as_header()) {
    (*auth_http_request.mutable_headers())["Authorization"] =
        absl::StrCat("Bearer ", auth_token.value());
  }

  // TODO: Clean up name of zinc_url.
  auth_http_request.set_url(config_.zinc_url());
  auth_call_time_ = absl::Now();
  http_fetcher_.PostJsonAsync(
      auth_http_request,
      absl::bind_front(&Auth::HandleAuthAndSignResponse, this, is_rekey));
}

absl::StatusOr<std::vector<RSABlindSignatureTokenWithInput>>
Auth::UnblindATToken() {
  if (!config_.public_metadata_enabled()) {
    LOG(ERROR)
        << "AT token unblinding only possible when public metadata is enabled";
    return absl::InternalError(
        "AT token unblinding only possible when public metadata is enabled");
  }
  // Create vector of unblinded anonymous tokens.
  AnonymousTokensSignResponse at_sign_response;

  if (auth_and_sign_response_.blinded_token_signatures().size() !=
      at_sign_request_.blinded_tokens_size()) {
    LOG(ERROR) << "Response signature size does not equal request tokens size. "
               << auth_and_sign_response_.blinded_token_signatures().size()
               << " != " << at_sign_request_.blinded_tokens_size();
    return absl::InternalError(
        "Response signature size does not equal request tokens size");
  }
  // This depends on the signing server returning the signatures in the order
  // that the tokens were sent. Phosphor does guarantee this.
  for (int i = 0; i < auth_and_sign_response_.blinded_token_signatures().size();
       i++) {
    std::string blinded_token;
    if (!absl::Base64Unescape(
            auth_and_sign_response_.blinded_token_signatures().at(i),
            &blinded_token)) {
      LOG(ERROR) << "Failed to unescape blinded token signature";
      return absl::InternalError("Failed to unescape blinded token signature");
    }
    AnonymousTokensSignResponse::AnonymousToken anon_token_proto;
    *anon_token_proto.mutable_use_case() =
        at_sign_request_.blinded_tokens(i).use_case();
    anon_token_proto.set_key_version(
        at_sign_request_.blinded_tokens(i).key_version());
    *anon_token_proto.mutable_public_metadata() =
        at_sign_request_.blinded_tokens(i).public_metadata();
    *anon_token_proto.mutable_serialized_blinded_message() =
        at_sign_request_.blinded_tokens(i).serialized_token();
    *anon_token_proto.mutable_serialized_token() = blinded_token;
    at_sign_response.add_anonymous_tokens()->Swap(&anon_token_proto);
  }

  auto signed_tokens = bssa_client_->ProcessResponse(at_sign_response);
  if (!signed_tokens.ok()) {
    LOG(ERROR) << "AuthAndSign ProcessResponse failed: "
               << signed_tokens.status();
    return signed_tokens.status();
  }
  if (signed_tokens->size() !=
      static_cast<size_t>(at_sign_response.anonymous_tokens_size())) {
    LOG(ERROR)
        << "ProcessResponse did not output the right number of signed tokens";
    return absl::InternalError(
        "ProcessResponse did not output the right number of signed tokens");
  }
  return signed_tokens;
}

absl::StatusOr<std::vector<RSABlindSignatureTokenWithInput>>
Auth::GetUnblindedATToken() const {
  absl::MutexLock l(&mutex_);
  return signed_tokens_;
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
