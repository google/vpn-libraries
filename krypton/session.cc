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

#include "privacy/net/krypton/session.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/protobuf/duration.proto.h"
#include "privacy/net/common/proto/update_path_info.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/network_info.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {
namespace {

constexpr int kInvalidTimerId = -1;
constexpr absl::Duration kFetchTimerDuration = absl::Minutes(5);
constexpr absl::Duration kDatapathReattemptDuration = absl::Milliseconds(500);
constexpr absl::Duration kDefaultRekeyDuration = absl::Hours(24);

// Reattempts excludes the first attempt.
constexpr char kDefaultCopperAddress[] = "na.b.g-tun.com";

std::string StateString(Session::State state) {
  switch (state) {
    case Session::State::kInitialized:
      return "kInitialized";
    case Session::State::kEgressSessionCreated:
      return "kEgressSessionCreated";
    case Session::State::kConnected:
      return "kConnected";
    case Session::State::kSessionError:
      return "kSessionError";
    case Session::State::kPermanentError:
      return "kPermanentError";
  }
}

absl::StatusOr<TunFdData::IpRange> ProtoIpRange(absl::string_view ip_address) {
  TunFdData::IpRange proto_ip_range;
  PPN_ASSIGN_OR_RETURN(auto ip_range, utils::IPRange::Parse(ip_address));

  proto_ip_range.set_ip_range(ip_range.address());
  if (ip_range.family() != 0) {
    proto_ip_range.set_ip_family(ip_range.family() == AF_INET
                                     ? TunFdData::IpRange::IPV4
                                     : TunFdData::IpRange::IPV6);
  }
  if (ip_range.prefix()) {
    proto_ip_range.set_prefix(ip_range.prefix().value());
  }
  return proto_ip_range;
}

absl::StatusOr<TunFdData::IpRange> ToTunFdIpRange(
    const privacy::ppn::IpRange& ip_range) {
  switch (ip_range.ip_case()) {
    case privacy::ppn::IpRange::kIpv4Range:
      return ProtoIpRange(ip_range.ipv4_range());
    case privacy::ppn::IpRange::kIpv6Range:
      return ProtoIpRange(ip_range.ipv6_range());
    default:
      return absl::InvalidArgumentError("ip range is neither IPv4 nor IPv6");
  }
}

void AddDns(absl::string_view dns_ip, TunFdData::IpRange::IpFamily family,
            uint32_t prefix, TunFdData::IpRange* ip_range) {
  ip_range->set_ip_family(family);
  ip_range->set_ip_range(dns_ip);
  ip_range->set_prefix(prefix);
}

}  // namespace

Session::Session(const KryptonConfig& config, Auth* auth,
                 EgressManager* egress_manager, DatapathInterface* datapath,
                 VpnServiceInterface* vpn_service, TimerManager* timer_manager,
                 HttpFetcherInterface* http_fetcher,
                 TunnelManagerInterface* tunnel_manager,
                 std::optional<NetworkInfo> network_info,
                 utils::LooperThread* notification_thread)
    : config_(config),
      auth_(ABSL_DIE_IF_NULL(auth)),
      egress_manager_(ABSL_DIE_IF_NULL(egress_manager)),
      datapath_(ABSL_DIE_IF_NULL(datapath)),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)),
      datapath_address_selector_(config) {
  // Register all state machine events to be sent to Session.
  auth_->RegisterNotificationHandler(this);
  egress_manager->RegisterNotificationHandler(this);
  datapath->RegisterNotificationHandler(this);
  active_network_info_ = network_info;
  key_material_ = std::make_unique<crypto::SessionCrypto>(config);
  auth_->SetCrypto(key_material_.get());
  tunnel_manager_ = tunnel_manager;
}

Session::~Session() {
  {
    absl::MutexLock l(&mutex_);
    CancelDatapathReattemptTimerIfRunning();
    CancelFetcherTimerIfRunning();
    CancelDatapathReattemptTimerIfRunning();
  }
}

void Session::CancelFetcherTimerIfRunning() {
  if (fetch_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(fetch_timer_id_);
  }
  fetch_timer_id_ = kInvalidTimerId;
}

void Session::CancelDatapathReattemptTimerIfRunning() {
  if (datapath_reattempt_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(datapath_reattempt_timer_id_);
  }
  datapath_reattempt_timer_id_ = kInvalidTimerId;
}

std::string ProtoToJsonString(const ppn::UpdatePathInfo& update_path_info) {
  std::string verification_key_encoded;
  std::string mtu_update_signature_encoded;
  absl::Base64Escape(update_path_info.verification_key(),
                     &verification_key_encoded);
  absl::Base64Escape(update_path_info.mtu_update_signature(),
                     &mtu_update_signature_encoded);

  nlohmann::json json_obj;
  json_obj[JsonKeys::kSessionId] = update_path_info.session_id();
  json_obj[JsonKeys::kSequenceNumber] = update_path_info.sequence_number();
  json_obj[JsonKeys::kMtu] = update_path_info.mtu();
  json_obj[JsonKeys::kVerificationKey] = verification_key_encoded;
  json_obj[JsonKeys::kMtuUpdateSignature] = mtu_update_signature_encoded;
  return utils::JsonToString(json_obj);
}

absl::Status Session::SendPathInfoUpdate() {
  privacy::ppn::UpdatePathInfo mtu_update;
  mtu_update.set_session_id(egress_manager_->uplink_spi());
  mtu_update.set_sequence_number(path_info_seq_++);
  mtu_update.set_mtu(path_mtu_);

  std::string signed_data = absl::StrCat("path_info;", mtu_update.session_id(),
                                         ";", mtu_update.mtu());

  PPN_ASSIGN_OR_RETURN(auto signature,
                       key_material_->GenerateSignature(signed_data));
  mtu_update.set_mtu_update_signature(signature);

  auto path_info_update_json = ProtoToJsonString(mtu_update);

  // TODO: Update to send to Brass or Beryllium once the handler
  // has been set up.

  return absl::OkStatus();
}

void Session::SetState(State state, absl::Status status) {
  LOG(INFO) << "Transitioning from " << StateString(state_) << " to "
            << StateString(state);
  state_ = state;
  latest_status_ = status;
  // Make a copy of the notification reference, to be used in the notification
  // closures sent to the notification thread, in case `this` is destroyed
  // before the notifications get run.
  NotificationInterface* notification = notification_;
  switch (state) {
    case State::kInitialized:
    case State::kEgressSessionCreated:
      break;
    case State::kConnected:
      notification_thread_->Post(
          [notification] { notification->ControlPlaneConnected(); });
      StartFetchCountersTimer();
      break;
    case State::kSessionError:
      notification_thread_->Post([notification, status] {
        notification->ControlPlaneDisconnected(status);
      });
      break;
    case State::kPermanentError:
      notification_thread_->Post(
          [notification, status] { notification->PermanentFailure(status); });
      break;
  }
}

void Session::Start() {
  absl::MutexLock l(&mutex_);
  DCHECK(notification_);
  LOG(INFO) << "Starting session";
  tunnel_manager_->StartSession();
  auth_->Start(/*is_rekey=*/false);
}

void Session::Stop(bool forceFailOpen) {
  absl::MutexLock l(&mutex_);
  CancelFetcherTimerIfRunning();
  CancelDatapathReattemptTimerIfRunning();
  tunnel_manager_->TerminateSession(forceFailOpen);
}

void Session::PpnDataplaneRequest(bool is_rekey) {
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
    SetState(State::kSessionError, resolved_address.status());
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
  // Always send the region token and signature even if it's empty.
  params.region_token_and_signature =
      auth_response.region_token_and_signatures();
  params.apn_type = auth_response.apn_type();
  params.dynamic_mtu_enabled = config_.dynamic_mtu_enabled();
  if (config_.enable_blind_signing()) {
    params.blind_message = key_material_->original_message();
    std::string blinded_signature;
    if (auth_->auth_response().blinded_token_signatures().empty()) {
      LOG(ERROR) << "No blind token signatures found";
      auto status =
          absl::FailedPreconditionError("No blind token signatures found");
      SetState(State::kSessionError, status);
      return;
    }
    if (absl::Base64Unescape(
            auth_->auth_response().blinded_token_signatures().at(0),
            &blinded_signature)) {
      auto token = key_material_->GetBrassUnblindedToken(blinded_signature);
      if (!token.has_value()) {
        LOG(ERROR) << "No unblinded token signatures found";
        auto status = absl::FailedPreconditionError(
            "No unblinded token signatures found");
        SetState(State::kSessionError, status);
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

  auto status = egress_manager_->GetEgressNodeForPpnIpSec(params);
  if (!status.ok()) {
    LOG(ERROR) << "GetEgressNodeForPpnIpSec failed";
    SetState(State::kSessionError, status);
  }
}

void Session::AuthSuccessful(bool is_rekey) {
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

void Session::AuthFailure(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  if (utils::IsPermanentError(status)) {
    SetState(State::kPermanentError, status);
  } else {
    SetState(State::kSessionError, status);
  }
}

absl::Status Session::BuildTunFdData(TunFdData* tun_fd_data) const {
  PPN_ASSIGN_OR_RETURN(auto egress_data,
                       egress_manager_->GetEgressSessionDetails());

  tun_fd_data->set_is_metered(false);
  if (config_.dynamic_mtu_enabled()) {
    tun_fd_data->set_mtu(1396);
  }

  // Explicitly set the IPv4 DNS
  AddDns("8.8.8.8", TunFdData::IpRange::IPV4, 32,
         tun_fd_data->add_tunnel_dns_addresses());
  AddDns("8.8.4.4", TunFdData::IpRange::IPV4, 32,
         tun_fd_data->add_tunnel_dns_addresses());

  // Explicitly set the IPv6 DNS
  AddDns("2001:4860:4860::8888", TunFdData::IpRange::IPV6, 128,
         tun_fd_data->add_tunnel_dns_addresses());
  AddDns("2001:4860:4860::8844", TunFdData::IpRange::IPV6, 128,
         tun_fd_data->add_tunnel_dns_addresses());

  PPN_ASSIGN_OR_RETURN(auto ppn_info, egress_data.ppn_dataplane_response());

  if (ppn_info.user_private_ip_size() == 0) {
    return absl::InvalidArgumentError("missing user_private_ip");
  }
  auto ip_ranges = ppn_info.user_private_ip();
  for (const auto& ip : ip_ranges) {
    PPN_ASSIGN_OR_RETURN(auto proto_ip_range, ToTunFdIpRange(ip));
    *(tun_fd_data->add_tunnel_ip_addresses()) = proto_ip_range;
  }

  return absl::OkStatus();
}

absl::Status Session::CreateTunnelIfNeeded() {
  if (has_active_tunnel_) {
    LOG(INFO) << "Not creating tun fd as it's already present";
    return absl::OkStatus();
  }

  TunFdData tun_fd_data;
  auto active_network_info = active_network_info_;
  DCHECK(active_network_info);

  auto build_tun_status = BuildTunFdData(&tun_fd_data);
  if (!build_tun_status.ok()) {
    SetState(State::kSessionError, build_tun_status);
    return build_tun_status;
  }
  // If bringing up the tunnel fails, assume there is no tunnel. Technically,
  // the tunnel manager may leave the tunnel up even if there's an error with
  // the new one, but it won't hurt to request it again later.
  PPN_RETURN_IF_ERROR(tunnel_manager_->EnsureTunnelIsUp(tun_fd_data));
  has_active_tunnel_ = true;
  return absl::OkStatus();
}

absl::Status Session::SetRemoteKeyMaterial() {
  PPN_ASSIGN_OR_RETURN(auto egress, egress_manager_->GetEgressSessionDetails());
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

void Session::RekeyDatapath() {
  // Do the rekey procedures.
  LOG(INFO) << "Successful response from egress for rekey";
  auto transform_params = key_material_->GetTransformParams();
  if (!transform_params.ok()) {
    SetState(State::kSessionError, transform_params.status());
    return;
  }
  auto rekey_status = datapath_->SetKeyMaterials(*transform_params);
  if (!rekey_status.ok()) {
    SetState(State::kSessionError, rekey_status);
    return;
  }
  LOG(INFO) << "Rekey is successful";
  last_rekey_time_ = absl::Now();
  number_of_rekeys_.fetch_add(1);
}

void Session::EgressAvailable(bool is_rekey) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Establishing PpnDataplane [IPSec | Bridge]";
  // Set the last rekey. This could be the first one where it's initialized or
  // part of the rekey procedures.
  // Rekey is only valid for PpnDataPlane.
  last_rekey_time_ = absl::Now();

  auto status = SetRemoteKeyMaterial();
  if (!status.ok()) {
    LOG(ERROR) << "Error setting remote key material " << status;
    SetState(State::kSessionError, status);
    return;
  }

  if (datapath_ == nullptr) {
    LOG(ERROR) << "No datapath found while rekeying";
    SetState(State::kSessionError, absl::InternalError("datapath_ == nullptr"));
    return;
  }

  // Session start handling.
  if (!is_rekey) {
    SetState(State::kEgressSessionCreated, absl::OkStatus());
    ResetAllDatapathReattempts();
    StartDatapath();
    return;
  }

  RekeyDatapath();
}

absl::Status Session::Rekey() {
  if (state_ != State::kConnected) {
    return absl::FailedPreconditionError(
        "Session is not in connected state for rekey");
  }
  // Generate the rekey parameters that are needed and generate a signature from
  // the old crypto keys.
  auto new_key_material = std::make_unique<crypto::SessionCrypto>(config_);
  PPN_ASSIGN_OR_RETURN(auto signature,
                       key_material_->GeneratePublicValueSignature(
                           new_key_material->public_value()));
  new_key_material->SetSignature(signature);
  key_material_.reset();
  key_material_ = std::move(new_key_material);
  auth_->SetCrypto(key_material_.get());
  auth_->Start(/*is_rekey=*/true);
  return absl::OkStatus();
}

void Session::StartDatapath() {
  if (state_ != State::kEgressSessionCreated) {
    LOG(INFO) << "Tunnel FD is updated but not updating the datapath as the "
                 "session is in the wrong state "
              << StateString(state_);
    return;
  }
  auto egress_response = egress_manager_->GetEgressSessionDetails();
  if (!egress_response.ok()) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    SetState(State::kSessionError, egress_response.status());
    return;
  }

  // Check if the key material is set.
  auto transform_params = key_material_->GetTransformParams();
  if (!transform_params.ok()) {
    SetState(State::kSessionError, transform_params.status());
    return;
  }

  auto datapath_status = datapath_->Start(*egress_response, *transform_params);
  if (!datapath_status.ok()) {
    LOG(ERROR) << "Datapath initialization failed with status:"
               << datapath_status;
    if (utils::IsPermanentError(datapath_status)) {
      SetState(State::kPermanentError, datapath_status);
    }
    SetState(State::kSessionError, datapath_status);
    return;
  }
  // Datapath initialized is treated as connected event. In case of failure, we
  // should get a failure from datapath.
  SetState(State::kConnected, absl::OkStatus());

  if (!active_network_info_) {
    LOG(INFO) << "There is no active network info, waiting for SetNetwork";
    return;
  }
  LOG(INFO) << "Active network is available, switching the network";
  auto status = SwitchDatapath();
  if (!status.ok()) {
    LOG(ERROR) << "Switching datapath failed with status: " << status;
  }
}

void Session::StartFetchCountersTimer() {
  // Start fetching the counters every 5 mins.
  CancelFetcherTimerIfRunning();
  LOG(INFO) << "Starting FetchCounters timer.";
  auto timer_id = timer_manager_->StartTimer(
      kFetchTimerDuration, absl::bind_front(&Session::FetchCounters, this));
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for fetch counters";
    return;
  }
  fetch_timer_id_ = *timer_id;
}

void Session::StartDatapathReattemptTimer() {
  CancelDatapathReattemptTimerIfRunning();
  LOG(INFO) << "Starting Datapath reattempt timer.";
  auto timer_id = timer_manager_->StartTimer(
      kDatapathReattemptDuration,
      absl::bind_front(&Session::AttemptDatapathReconnect, this));
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for DatapathReattempt";
    return;
  }

  datapath_reattempt_timer_id_ = *timer_id;
}

void Session::FetchCounters() {
  absl::MutexLock l(&mutex_);
  if (fetch_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Fetch timer is already cancelled";
    return;
  }

  fetch_timer_id_ = kInvalidTimerId;
  LOG(INFO) << "Fetching counters";

  if (absl::Now() - last_rekey_time_ >
      (config_.has_rekey_duration()
           ? absl::Seconds(config_.rekey_duration().seconds())
           : kDefaultRekeyDuration)) {
    LOG(INFO) << "Starting Rekey procedures";
    auto status = Rekey();
    if (!status.ok()) {
      LOG(INFO) << "Rekey status " << status;
      SetState(State::kSessionError, status);
      return;
    }
  }
  StartFetchCountersTimer();
}

std::optional<NetworkInfo> Session::active_network_info() const {
  absl::MutexLock l(&mutex_);
  return active_network_info_;
}

void Session::EgressUnavailable(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  LOG(ERROR) << "Egress unavailable with status: " << status;
  SetState(State::kSessionError, status);
}

void Session::DatapathEstablished() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Datapath is established";
  datapath_connected_ = true;
  ResetAllDatapathReattempts();
  auto notification = notification_;
  notification_thread_->Post(
      [notification] { notification->DatapathConnected(); });
}

void Session::ResetAllDatapathReattempts() {
  LOG(INFO) << "Resetting all datapath reattempts";
  CancelDatapathReattemptTimerIfRunning();
  datapath_reattempt_timer_id_ = kInvalidTimerId;
  datapath_reattempt_count_ = 0;
  LOG(INFO) << "Resetting address selector with "
            << egress_manager_->egress_node_sock_addresses().size()
            << " possible addresses with "
            << (active_network_info_ ? "an active network" : "no network");
  datapath_address_selector_.Reset(
      egress_manager_->egress_node_sock_addresses(), active_network_info_);
}

void Session::AttemptDatapathReconnect() {
  absl::MutexLock l(&mutex_);
  NetworkInfo new_network_info;
  LOG(INFO) << "Datapath reconnect timer expiry";

  if (datapath_reattempt_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Datapath attempt timer is already cancelled, not doing any "
                 "datapath reconnect.";
    return;
  }
  datapath_reattempt_timer_id_ = kInvalidTimerId;

  // While waiting to reconnect timer, datapath could be established as the
  // network fd is not withdrawn from the datapath.
  if (datapath_connected_) {
    LOG(INFO) << "Datapath is already connected, not reattempting";
    // Do nothing and return as datapath came up.
    return;
  }

  // Check if there is active network.
  if (!active_network_info_) {
    auto status = latest_datapath_status_;
    auto* notification = notification_;
    notification_thread_->Post([notification, status] {
      notification->DatapathDisconnected(NetworkInfo(), status);
    });
    return;
  }

  // Everything looks good as we got a new network fd, switch datapath.
  auto status = SwitchDatapath();
  if (!status.ok()) {
    LOG(ERROR) << "Switch datapath failed with status:" << status;
  }
}

void Session::DatapathFailed(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  if (!active_network_info_) {
    LOG(INFO) << "Received event after network info was reset.";
    return;
  }

  LOG(ERROR) << "Datapath Failed with status:" << status;
  datapath_connected_ = false;
  latest_datapath_status_ = status;

  // For failures on datapath, see if we can reattempt.
  // Check if there are more datapaths.
  if (datapath_address_selector_.HasMoreAddresses()) {
    LOG(INFO) << "Datapath attempt " << datapath_reattempt_count_
              << " failed, waiting to see if it can get reconnected.";
    datapath_reattempt_count_++;
    StartDatapathReattemptTimer();
    return;
  }

  LOG(ERROR)
      << "Not reattempting datapath connection. Exhausted all addresses.";

  // Datapath failure is not treated as session failure. These are
  // notifications to the upper layers to fix the network.
  auto active_network_info_opt = active_network_info_;
  auto* notification = notification_;
  notification_thread_->Post([notification, status, active_network_info_opt] {
    notification->DatapathDisconnected(active_network_info_opt
                                           ? active_network_info_opt.value()
                                           : NetworkInfo(),
                                       status);
  });
}

void Session::DatapathPermanentFailure(const absl::Status& status) {
  LOG(ERROR) << "Datapath has permanent failure with status " << status;
  // Send notification to reconnector that will automatically reconnect the
  // session. Permanent failures have to be terminated and a new session needs
  // to be created.
  auto* notification = notification_;
  notification_thread_->Post([notification, status] {
    notification->DatapathDisconnected(NetworkInfo(), status);
  });
}

void Session::UpdateActiveNetworkInfo(std::optional<NetworkInfo> network_info) {
  // Based on the feedback from Android Eng, underlying network should be the
  // right choice and IsMetered should only be used when VPN itself is charging.
  active_network_info_ = network_info;
}

absl::Status Session::SetNetwork(std::optional<NetworkInfo> network_info) {
  absl::MutexLock l(&mutex_);
  if (network_info) {
    LOG(INFO) << "Switching network to "
              << utils::NetworkInfoDebugString(*network_info);
  } else {
    LOG(INFO) << "Switching network to null network.";
  }
  UpdateActiveNetworkInfo(network_info);
  ResetAllDatapathReattempts();

  if (state_ != State::kConnected) {
    LOG(INFO) << "Session is not in connected state, caching active network fd";
    return absl::OkStatus();
  }

  return SwitchDatapath();
}

absl::Status Session::SwitchDatapath() {
  if (active_network_info_) {
    LOG(INFO) << "Switching Network to network of type "
              << active_network_info_->network_type();
  } else {
    LOG(INFO) << "Removing all networks in SwitchDatapath";
  }

  if (datapath_ == nullptr) {
    LOG(ERROR) << "Datapath is not initialized";
    auto status = absl::FailedPreconditionError("Datapath is not initialized");
    SetState(State::kSessionError, status);
    return status;
  }

  // This value is not used here, but will be fetched again by
  // CreateTunnelIfNeeded. This check may or may not be helpful.
  auto egress_response = egress_manager_->GetEgressSessionDetails();
  if (!egress_response.ok()) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    SetState(State::kSessionError, egress_response.status());
    return egress_response.status();
  }

  auto tunnel_status = CreateTunnelIfNeeded();
  if (!tunnel_status.ok()) {
    LOG(ERROR) << "Tunnel creation failed with status " << tunnel_status;
    SetState(State::kSessionError, tunnel_status);
    return tunnel_status;
  }
  LOG(INFO) << "Got tunnel";

  auto current_restart_counter = network_switches_count_.fetch_add(1);
  if (active_network_info_) {
    LOG(INFO) << "SwitchDatapath Counter " << current_restart_counter
              << " for network type " << active_network_info_->network_type();
  } else {
    LOG(INFO) << "SwitchDatapath removing all networks";
  }

  PPN_ASSIGN_OR_RETURN(const auto& ip,
                       datapath_address_selector_.SelectDatapathAddress());

  auto switch_data_status =
      datapath_->SwitchNetwork(egress_manager_->uplink_spi(), ip,
                               active_network_info_, current_restart_counter);

  if (!switch_data_status.ok()) {
    LOG(ERROR) << "Switching networks failed: " << switch_data_status;
    auto active_network_info_opt = active_network_info_;
    auto* notification = notification_;
    const auto& status = switch_data_status;
    auto network_info = active_network_info_opt
                            ? active_network_info_opt.value()
                            : NetworkInfo();
    notification_thread_->Post([notification, status, network_info] {
      notification->DatapathDisconnected(network_info, status);
    });
  }

  return switch_data_status;
}

void Session::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);

  telemetry->set_successful_rekeys(number_of_rekeys_.load());
  number_of_rekeys_ = 0;
  auto delta_network_switches =
      network_switches_count_ - last_repoted_network_switches_;
  telemetry->set_network_switches(delta_network_switches);
  last_repoted_network_switches_ = delta_network_switches;
}

void Session::GetDebugInfo(SessionDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);

  debug_info->set_state(StateString(state_));
  debug_info->set_status(latest_status_.ToString());
  if (active_network_info_) {
    debug_info->mutable_active_network()->CopyFrom(
        active_network_info_.value());
  }
  debug_info->set_successful_rekeys(number_of_rekeys_.load());
  auto delta_network_switches =
      network_switches_count_ - last_repoted_network_switches_;
  debug_info->set_network_switches(delta_network_switches);

  if (datapath_ != nullptr) {
    datapath_->GetDebugInfo(debug_info->mutable_datapath());
  }
}

void Session::DoRekey() {
  absl::MutexLock l(&mutex_);
  auto status = Rekey();
  if (!status.ok()) {
    LOG(ERROR) << "Rekey procedure failed";
    SetState(State::kSessionError, status);
  }
}
}  // namespace krypton
}  // namespace privacy
