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

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

// Reattempts excludes the first attempt.
constexpr char kDefaultCopperAddress[] = "na.b.g-tun.com";

}  // namespace

Provision::Provision(const KryptonConfig& config, Auth* auth,
                     EgressManager* egress_manager,
                     HttpFetcherInterface* http_fetcher,
                     utils::LooperThread* notification_thread)
    : config_(config),
      auth_(ABSL_DIE_IF_NULL(auth)),
      egress_manager_(ABSL_DIE_IF_NULL(egress_manager)),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)) {
  auth_->RegisterNotificationHandler(this);
  egress_manager->RegisterNotificationHandler(this);

  key_material_ = std::make_unique<crypto::SessionCrypto>(config);
  auth_->SetCrypto(key_material_.get());
}

void Provision::FailWithStatus(absl::Status status, bool permanent) {
  NotificationInterface* notification = notification_;
  notification_thread_->Post([notification, status, permanent] {
    notification->ProvisioningFailure(status, permanent);
  });
}

void Provision::Start() {
  absl::MutexLock l(&mutex_);
  DCHECK(notification_);
  LOG(INFO) << "Starting provisioning";
  auth_->Start(/*is_rekey=*/false);
}

void Provision::PpnDataplaneRequest(bool is_rekey) {
  LOG(INFO) << "Doing PPN dataplane request. Rekey:"
            << ((is_rekey == true) ? "True" : "False");
  AuthAndSignResponse auth_response = auth_->auth_response();
  // If auth_response specifies a copper control plane address, use it;
  // otherwise if there is config option for the address, use it.
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
  auto resolved_address = http_fetcher_.LookupDns(copper_hostname);
  if (!resolved_address.ok()) {
    FailWithStatus(resolved_address.status(), false);
    return;
  }

  auto copper_address_ = *resolved_address;
  LOG(INFO) << "Copper server address:" << copper_address_;
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.copper_control_plane_address = copper_address_;
  params.is_rekey = is_rekey;
  params.suite = config_.cipher_suite_key_length() == 256
                     ? ppn::PpnDataplaneRequest::AES256_GCM
                     : ppn::PpnDataplaneRequest::AES128_GCM;
  params.dataplane_protocol = config_.datapath_protocol();
  // Always send the region token and sig even if it's empty.
  params.region_token_and_signature =
      auth_response.region_token_and_signatures();
  params.apn_type = auth_response.apn_type();
  params.dynamic_mtu_enabled = config_.dynamic_mtu_enabled();
  if (config_.enable_blind_signing()) {
    params.blind_message = key_material_->original_message();
    std::string blinded_signature;
    if (auth_->auth_response().blinded_token_signatures().empty()) {
      LOG(ERROR) << "No blind token signatures found";
      FailWithStatus(
          absl::FailedPreconditionError("No blind token signatures found"),
          false);
      return;
    }
    if (absl::Base64Unescape(
            auth_->auth_response().blinded_token_signatures().at(0),
            &blinded_signature)) {
      auto token = key_material_->GetBrassUnblindedToken(blinded_signature);
      if (!token.has_value()) {
        LOG(ERROR) << "No unblinded token signatures found";
        FailWithStatus(absl::FailedPreconditionError(
                           "No unblinded token signatures found"),
                       false);
        return;
      }
      params.unblinded_token_signature = token.value();
    }
  }

  params.crypto = key_material_.get();
  if (key_material_->GetRekeySignature()) {
    params.signature = key_material_->GetRekeySignature().value();
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
    // expiration() nanos were verified to be zero in auth.cc
    params.expiration =
        absl::FromUnixSeconds(public_metadata.expiration().seconds());
  }

  auto status = egress_manager_->GetEgressNodeForPpnIpSec(params);
  if (!status.ok()) {
    LOG(ERROR) << "GetEgressNodeForPpnIpSec failed";
    FailWithStatus(status, false);
  }
}

void Provision::AuthSuccessful(bool is_rekey) {
  LOG(INFO) << "Authentication successful, fetching egress node details. Rekey:"
            << (is_rekey ? "True" : "False");

  absl::MutexLock l(&mutex_);
  if (is_rekey) {
    if (config_.datapath_protocol() == KryptonConfig::BRIDGE ||
        config_.datapath_protocol() == KryptonConfig::IPSEC) {
      PpnDataplaneRequest(/*rekey=*/true);
      return;
    }
  }
  PpnDataplaneRequest();
}

void Provision::AuthFailure(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  FailWithStatus(status, utils::IsPermanentError(status));
}

absl::Status Provision::SetRemoteKeyMaterial(const AddEgressResponse& egress) {
  if (config_.datapath_protocol() == KryptonConfig::IKE) {
    return absl::OkStatus();
  }

  PPN_ASSIGN_OR_RETURN(auto ppn_data_plane, egress.ppn_dataplane_response());
  if (ppn_data_plane.egress_point_public_value().empty()) {
    return absl::InvalidArgumentError("missing egress_point_public_value");
  }
  auto remote_public_value = ppn_data_plane.egress_point_public_value();
  if (ppn_data_plane.server_nonce().empty()) {
    return absl::InvalidArgumentError("missing server_nonce");
  }
  auto remote_nonce = ppn_data_plane.server_nonce();

  PPN_RETURN_IF_ERROR(
      key_material_->SetRemoteKeyMaterial(remote_public_value, remote_nonce));
  // Store the rekey_verification_key as it's needed for the next rekey
  // procedure.
  PPN_ASSIGN_OR_RETURN(rekey_verification_key_,
                       key_material_->GetRekeyVerificationKey());
  return absl::OkStatus();
}

void Provision::EgressAvailable(bool /*is_rekey*/) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Egress available";

  auto egress = egress_manager_->GetEgressSessionDetails();
  if (!egress.ok()) {
    LOG(ERROR) << "Error getting session details";
    FailWithStatus(egress.status(), false);
    return;
  }

  auto status = SetRemoteKeyMaterial(*egress);
  if (!status.ok()) {
    LOG(ERROR) << "Error setting remote key material " << status;
    FailWithStatus(status, false);
    return;
  }

  NotificationInterface* notification = notification_;
  notification_thread_->Post(
      [notification, status, egress] { notification->Provisioned(*egress); });
}

void Provision::EgressUnavailable(const absl::Status& status) {
  LOG(ERROR) << "Egress unavailable with status: " << status;
  FailWithStatus(status, false);
}

}  // namespace krypton
}  // namespace privacy
