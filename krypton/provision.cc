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

#include "privacy/net/krypton/provision.h"

#include <memory>
#include <string>
#include <utility>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/log/die_if_null.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

namespace privacy {
namespace krypton {
namespace {

using ::privacy::net::common::proto::PpnDataplaneResponse;

// Reattempts exclude the first attempt.
constexpr char kDefaultCopperAddress[] = "na4.p.g-tun.com";

constexpr int kControlPlanePort = 1849;

}  // namespace

Provision::Provision(const KryptonConfig& config, std::unique_ptr<Auth> auth,
                     std::unique_ptr<EgressManager> egress_manager,
                     HttpFetcherInterface* http_fetcher,
                     NotificationInterface* notification,
                     utils::LooperThread* notification_thread)
    : config_(config),
      looper_("Provision Looper"),
      auth_(std::move(ABSL_DIE_IF_NULL(auth))),
      egress_manager_(std::move(ABSL_DIE_IF_NULL(egress_manager))),
      notification_(ABSL_DIE_IF_NULL(notification)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)) {
  auth_->RegisterNotificationHandler(this, &looper_);
  egress_manager_->RegisterNotificationHandler(this, &looper_);
}

Provision::~Provision() {
  looper_.Stop();
  looper_.Join();
}

void Provision::FailWithStatus(absl::Status status) {
  NotificationInterface* notification = notification_;
  notification_thread_->Post([notification, status] {
    notification->ProvisioningFailure(status, utils::IsPermanentError(status));
  });
}

void Provision::Start() {
  absl::MutexLock l(&mutex_);
  DCHECK(notification_);
  LOG(INFO) << "Starting provisioning";
  auth_->Start(/*is_rekey=*/false);
}

void Provision::Stop() {
  absl::MutexLock l(&mutex_);
  auth_->Stop();
  egress_manager_->Stop();
}

void Provision::Rekey() {
  absl::MutexLock l(&mutex_);
  auth_->Start(/*is_rekey=*/true);
}

void Provision::SendAddEgress(bool is_rekey,
                              crypto::SessionCrypto* key_material) {
  absl::MutexLock l(&mutex_);
  PpnDataplaneRequest(is_rekey, key_material);
}

std::string Provision::GetApnType() {
  absl::MutexLock l(&mutex_);
  return auth_->auth_response().apn_type();
}

absl::StatusOr<std::string> Provision::GetControlPlaneAddr() {
  absl::MutexLock l(&mutex_);
  if (control_plane_addr_.empty()) {
    return absl::FailedPreconditionError("Control plane addr not set");
  }
  return control_plane_addr_;
}

void Provision::GetDebugInfo(KryptonDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  auth_->GetDebugInfo(debug_info->mutable_auth());
  egress_manager_->GetDebugInfo(debug_info->mutable_egress());
}

void Provision::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  auth_->CollectTelemetry(telemetry);
  egress_manager_->CollectTelemetry(telemetry);
}

void Provision::PpnDataplaneRequest(bool is_rekey,
                                    crypto::SessionCrypto* key_material) {
  LOG(INFO) << "Doing PPN dataplane request. Rekey:"
            << ((is_rekey == true) ? "True" : "False");
  AuthAndSignResponse auth_response = auth_->auth_response();
  // Rekey should use the same control plane address as was used for
  // the initial provisioning.
  // TODO : When using Oasis skip the DNS resolution.
  if (!is_rekey) {
    // If auth_response specifies a copper control plane address, use it;
    // otherwise if there is a config option for the address, use it.
    std::string copper_hostname;
    if (config_.has_copper_hostname_override() &&
        !config_.copper_hostname_override().empty()) {
      copper_hostname = config_.copper_hostname_override();
    } else if (!auth_response.copper_controller_hostname().empty()) {
      copper_hostname = auth_response.copper_controller_hostname();
    } else if (config_.has_copper_controller_address()) {
      copper_hostname = config_.copper_controller_address();
    } else {
      copper_hostname = kDefaultCopperAddress;
    }
    LOG(INFO) << "Copper hostname for DNS lookup: " << copper_hostname;
    absl::StatusOr<std::string> resolved_address =
        http_fetcher_.LookupDns(copper_hostname);
    if (!resolved_address.ok()) {
      FailWithStatus(resolved_address.status());
      return;
    }

    absl::StatusOr<utils::IPRange> ip_range =
        utils::IPRange::Parse(*resolved_address);
    if (!ip_range.ok()) {
      FailWithStatus(ip_range.status());
      return;
    }
    control_plane_addr_ = ip_range->HostPortString(kControlPlanePort);
  }
  LOG(INFO) << "Control plane addr:" << control_plane_addr_;
  AddEgressRequest::PpnDataplaneRequestParams params{};
  params.prefer_oasis = config_.prefer_oasis();
  params.use_reserved_ip_pool = config_.use_reserved_ip_pool();
  params.control_plane_sockaddr = control_plane_addr_;
  params.is_rekey = is_rekey;
  params.suite = config_.cipher_suite_key_length() == 256
                     ? net::common::proto::PpnDataplaneRequest::AES256_GCM
                     : net::common::proto::PpnDataplaneRequest::AES128_GCM;
  params.dataplane_protocol = config_.datapath_protocol();
  // Always send the region token and sig even if it's empty.
  params.region_token_and_signature =
      auth_response.region_token_and_signatures();
  params.apn_type = auth_response.apn_type();
  params.dynamic_mtu_enabled = config_.dynamic_mtu_enabled();
  if (config_.enable_blind_signing()) {
    params.blind_message = auth_->GetOriginalMessage();
    std::string blinded_signature;
    if (auth_->auth_response().blinded_token_signatures().empty()) {
      LOG(ERROR) << "No blind token signatures found";
      FailWithStatus(
          absl::FailedPreconditionError("No blind token signatures found"));
      return;
    }
    // set unblinded_token_signature
    if (config_.public_metadata_enabled()) {
      // TODO Add tests covering this if statement.
      auto signed_tokens = auth_->GetUnblindedAnonymousToken();
      if (!signed_tokens.ok()) {
        LOG(ERROR) << "No unblinded token signatures found";
        FailWithStatus(signed_tokens.status());
        return;
      }
      if (signed_tokens->size() != 1) {
        LOG(ERROR) << "Incorrect number of signed tokens found.";
        FailWithStatus(absl::FailedPreconditionError(
            "Incorrect number of signed tokens found"));
        return;
      }
      params.unblinded_token = signed_tokens->at(0).input().plaintext_message();
      params.unblinded_token_signature =
          absl::Base64Escape(signed_tokens->at(0).token().token());
      params.message_mask =
          absl::Base64Escape(signed_tokens->at(0).token().message_mask());
    } else if (absl::Base64Unescape(
                   auth_->auth_response().blinded_token_signatures().at(0),
                   &blinded_signature)) {
      auto token = auth_->GetBrassUnblindedToken(blinded_signature);
      if (!token.has_value()) {
        LOG(ERROR) << "No unblinded token signatures found";
        FailWithStatus(absl::FailedPreconditionError(
            "No unblinded token signatures found"));
        return;
      }
      params.unblinded_token_signature = token.value();
    }
  }

  params.crypto = key_material;
  if (key_material->GetRekeySignature()) {
    params.signature = key_material->GetRekeySignature().value();
  }
  params.uplink_spi = egress_manager_->uplink_spi();

  if (config_.public_metadata_enabled()) {
    auto get_initial_data_response = auth_->initial_data_response();
    auto public_metadata =
        get_initial_data_response.public_metadata_info().public_metadata();

    params.signing_key_version =
        get_initial_data_response.at_public_metadata_public_key().key_version();
    params.country = public_metadata.exit_location().country();
    params.city_geo_id = public_metadata.exit_location().city_geo_id();
    params.service_type = public_metadata.service_type();
    params.debug_mode = public_metadata.debug_mode();
    // expiration() nanos were verified to be zero in auth.cc
    params.expiration =
        absl::FromUnixSeconds(public_metadata.expiration().seconds());
  }

  auto status = egress_manager_->GetEgressNodeForPpnIpSec(params);
  if (!status.ok()) {
    LOG(ERROR) << "GetEgressNodeForPpnIpSec failed";
    FailWithStatus(status);
  }
}

void Provision::AuthSuccessful(bool is_rekey) {
  LOG(INFO) << "Authentication successful, fetching egress node details. Rekey:"
            << (is_rekey ? "True" : "False");
  absl::MutexLock l(&mutex_);
  NotificationInterface* notification = notification_;
  notification_thread_->Post(
      [notification, is_rekey] { notification->ReadyForAddEgress(is_rekey); });
}

void Provision::AuthFailure(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  LOG(ERROR) << "Authentication failed: " << status;
  FailWithStatus(status);
}

void Provision::EgressAvailable(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Egress available";

  absl::StatusOr<AddEgressResponse> egress =
      egress_manager_->GetEgressSessionDetails();
  if (!egress.ok()) {
    LOG(ERROR) << "Error getting session details";
    FailWithStatus(egress.status());
    return;
  }

  if (!is_rekey) {
    // Attempt to parse a control plane sockaddr from the response.
    absl::StatusOr<PpnDataplaneResponse> ppn_dataplane =
        egress->ppn_dataplane_response();
    if (ppn_dataplane.ok()) {
      ParseControlPlaneSockaddr(*ppn_dataplane);
    }
  }

  NotificationInterface* notification = notification_;
  notification_thread_->Post([notification, egress, is_rekey] {
    notification->Provisioned(*egress, is_rekey);
  });
}

void Provision::ParseControlPlaneSockaddr(
    const PpnDataplaneResponse& ppn_dataplane) {
  if (!ppn_dataplane.control_plane_addr().empty()) {
    LOG(INFO) << "Control plane addr received in AddEgressResponse: "
              << ppn_dataplane.control_plane_addr();
    control_plane_addr_ = ppn_dataplane.control_plane_addr();
  }
}

void Provision::EgressUnavailable(const absl::Status& status) {
  LOG(ERROR) << "Egress unavailable with status: " << status;
  FailWithStatus(status);
}

}  // namespace krypton
}  // namespace privacy
