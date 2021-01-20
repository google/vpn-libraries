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

#include "privacy/net/krypton/session.h"

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/ip_range.h"
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

namespace privacy {
namespace krypton {
namespace {

constexpr int kInvalidFd = -1;
constexpr int kInvalidTimerId = -1;
constexpr absl::Duration kFetchTimerDuration = absl::Minutes(5);
constexpr absl::Duration kDatapathReattemptDuration = absl::Milliseconds(500);
constexpr absl::Duration kDefaultRekeyDuration = absl::Hours(24);

// Reattempts excludes the first attempt.
constexpr int MAX_DATAPATH_REATTEMPTS = 3;
constexpr int MAX_ATTEMPTS_PER_ADDRESS_FAMILY = 2;
constexpr char kDefaultCopperAddress[] = "na.b.g-tun.com";

std::string StateString(Session::State state) {
  switch (state) {
    case Session::State::kInitialized:
      return "kInitialized";
    case Session::State::kAuthSuccessful:
      return "kAuthSuccessful";
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

bool IsReattemptable(const absl::Status& status) {
  // If the status code is deadline exceeded. Do not reattempt as the datapath
  // already retried.
  if (status.code() == absl::StatusCode::kDeadlineExceeded) {
    return false;
  }
  return true;
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
            uint32 prefix, TunFdData::IpRange* ip_range) {
  ip_range->set_ip_family(family);
  ip_range->set_ip_range(dns_ip);
  ip_range->set_prefix(prefix);
}

}  // namespace

Session::Session(Auth* auth, EgressManager* egress_manager,
                 DatapathInterface* datapath, VpnServiceInterface* vpn_service,
                 TimerManager* timer_manager,
                 absl::optional<NetworkInfo> network_info,
                 KryptonConfig* config,
                 utils::LooperThread* notification_thread)
    : auth_(ABSL_DIE_IF_NULL(auth)),
      egress_manager_(ABSL_DIE_IF_NULL(egress_manager)),
      datapath_(ABSL_DIE_IF_NULL(datapath)),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      config_(ABSL_DIE_IF_NULL(config)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)) {
  // Register all state machine events to be sent to Session.
  auth_->RegisterNotificationHandler(this);
  egress_manager->RegisterNotificationHandler(this);
  datapath->RegisterNotificationHandler(this);
  active_network_info_ = network_info;
  key_material_ = absl::make_unique<crypto::SessionCrypto>();
  auth_->SetCrypto(key_material_.get());
}

Session::~Session() {
  {
    absl::MutexLock l(&mutex_);
    CancelDatapathReattemptTimerIfRunning();
    CancelFetcherTimerIfRunning();
  }
  ResetAllDatapathReattempts();
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

void Session::SetState(State state) {
  LOG(INFO) << "Transitioning from " << StateString(state_) << " to "
            << StateString(state);
  state_ = state;
  // Make a copy of the notification reference, to be used in the notification
  // closures sent to the notification thread, in case `this` is destroyed
  // before the notifications get run.
  NotificationInterface* notification = notification_;
  auto status = latest_status_;
  switch (state) {
    case State::kInitialized:
    case State::kAuthSuccessful:
      break;
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

void Session::UpdateLatestStatus(const absl::Status& status) {
  latest_status_ = status;
  LOG(ERROR) << "Session error with Status:" << status;
}

void Session::UpdateLatestDatapathStatus(const absl::Status& status) {
  latest_datapath_status_ = status;
}

void Session::Start() {
  absl::MutexLock l(&mutex_);
  DCHECK(notification_);
  LOG(INFO) << "Starting session";
  auth_->Start(/*is_rekey=*/false);
}

void Session::Stop() {
  absl::MutexLock l(&mutex_);
  CancelFetcherTimerIfRunning();
  CancelDatapathReattemptTimerIfRunning();
}

void Session::PpnDataplaneRequest(bool is_rekey) {
  LOG(INFO) << "Doing PPN dataplane request. Rekey:"
            << ((is_rekey == true) ? "True" : "False");
  // If there is config option for copper control plane address, use it.
  auto status_or_resolved_address =
      utils::ResolveIPV4Address(config_->has_copper_controller_address()
                                    ? config_->copper_controller_address()
                                    : kDefaultCopperAddress);
  if (!status_or_resolved_address.ok()) {
    UpdateLatestStatus(status_or_resolved_address.status());
    SetState(State::kSessionError);
    return;
  }

  auto copper_address_ = status_or_resolved_address.value();
  LOG(INFO) << "Copper server address:" << copper_address_;
  AddEgressRequest::PpnDataplaneRequestParams params;
  params.auth_response = auth_->auth_response();
  params.copper_control_plane_address = copper_address_;
  params.is_rekey = is_rekey;
  params.suite = config_->cipher_suite_key_length() == 256
                     ? CryptoSuite::AES256_GCM
                     : CryptoSuite::AES128_GCM;
  params.dataplane_protocol = config_->bridge_over_ppn()
                                  ? DataplaneProtocol::BRIDGE
                                  : DataplaneProtocol::IPSEC;
  if (config_->enable_blind_signing()) {
    params.blind_token_enabled = true;
    params.blind_message = key_material_->original_message();
    std::string blinded_signature;
    if (auth_->auth_response()->blinded_token_signatures().empty()) {
      UpdateLatestStatus(
          absl::FailedPreconditionError("No blind token signatures found"));
      SetState(State::kSessionError);
      return;
    }
    if (absl::Base64Unescape(
            auth_->auth_response()->blinded_token_signatures().at(0),
            &blinded_signature)) {
      params.unblinded_token_signature =
          key_material_->GetBrassUnblindedToken(blinded_signature).value();
    }
  }

  params.crypto = key_material_.get();
  if (key_material_->GetRekeySignature()) {
    params.signature = key_material_->GetRekeySignature().value();
  }
  params.uplink_spi = egress_manager_->uplink_spi();

  auto status = egress_manager_->GetEgressNodeForPpnIpSec(params);
  if (!status.ok()) {
    UpdateLatestStatus(status);
    SetState(State::kSessionError);
  }
}

void Session::AuthSuccessful(bool is_rekey) {
  LOG(INFO) << "Authentication successful, fetching egress node details. Rekey:"
            << (is_rekey ? "True" : "False");

  absl::MutexLock l(&mutex_);
  if (is_rekey) {
    if (config_->ipsec_datapath() || config_->bridge_over_ppn()) {
      PpnDataplaneRequest(/*rekey=*/true);
      return;
    }
  }
  // If we are running IPSec or Bridge using PPN protocol, send PpnDataplane
  // request.
  if (config_->ipsec_datapath() || config_->bridge_over_ppn()) {
    PpnDataplaneRequest();
    return;
  }
  auto status = egress_manager_->GetEgressNodeForBridge(auth_->auth_response());
  if (!status.ok()) {
    UpdateLatestStatus(status);
    SetState(State::kSessionError);
  }
}

void Session::AuthFailure(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  UpdateLatestStatus(status);
  if (utils::IsPermanentError(status.code())) {
    SetState(State::kPermanentError);
  } else {
    SetState(State::kSessionError);
  }
}

absl::Status Session::BuildTunFdData(TunFdData* tun_fd_data) const {
  PPN_ASSIGN_OR_RETURN(auto egress_data,
                       egress_manager_->GetEgressSessionDetails());

  // Explicitly set the IPv4 DNS
  AddDns("8.8.8.8", TunFdData::IpRange::IPV4, 32,
         tun_fd_data->add_tunnel_dns_addresses());
  AddDns("8.8.8.4", TunFdData::IpRange::IPV4, 32,
         tun_fd_data->add_tunnel_dns_addresses());

  // Explicitly set the IPv6 DNS
  AddDns("2001:4860:4860::8888", TunFdData::IpRange::IPV6, 128,
         tun_fd_data->add_tunnel_dns_addresses());
  AddDns("2001:4860:4860::8844", TunFdData::IpRange::IPV6, 128,
         tun_fd_data->add_tunnel_dns_addresses());

  PPN_ASSIGN_OR_RETURN(auto ppn_info, egress_data->ppn_dataplane_response());

  if (ppn_info->user_private_ip_size() == 0) {
    return absl::InvalidArgumentError("missing user_private_ip");
  }
  auto ip_ranges = ppn_info->user_private_ip();
  for (const auto& ip : ip_ranges) {
    PPN_ASSIGN_OR_RETURN(auto proto_ip_range, ToTunFdIpRange(ip));
    *(tun_fd_data->add_tunnel_ip_addresses()) = proto_ip_range;
  }

  return absl::OkStatus();
}

absl::Status Session::CreateTunnelIfNeeded() {
  if (active_tunnel_ != nullptr) {
    LOG(INFO) << "Not creating tun fd as it's already present";
    return absl::OkStatus();
  }

  TunFdData tun_fd_data;
  auto active_network_info = active_network_info_;
  DCHECK(active_network_info);

  tun_fd_data.set_is_metered(false);
  auto build_tun_status = BuildTunFdData(&tun_fd_data);
  if (!build_tun_status.ok()) {
    UpdateLatestStatus(build_tun_status);
    SetState(State::kSessionError);
    return build_tun_status;
  }
  PPN_ASSIGN_OR_RETURN(auto tunnel, vpn_service_->CreateTunnel(tun_fd_data));
  active_tunnel_ = std::move(tunnel);
  return absl::OkStatus();
}

absl::Status Session::SetRemoteKeyMaterial() {
  PPN_ASSIGN_OR_RETURN(auto egress, egress_manager_->GetEgressSessionDetails());
  PPN_ASSIGN_OR_RETURN(auto ppn_data_plane, egress->ppn_dataplane_response());
  if (ppn_data_plane->egress_point_public_value().empty()) {
    return absl::InvalidArgumentError("missing egress_point_public_value");
  }
  auto remote_public_value = ppn_data_plane->egress_point_public_value();
  if (ppn_data_plane->server_nonce().empty()) {
    return absl::InvalidArgumentError("missing server_nonce");
  }
  auto remote_nonce = ppn_data_plane->server_nonce();

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
  auto status_or_bridge_transform_params =
      key_material_->GetBridgeTransformParams(
          config_->cipher_suite_key_length() == 128 ? CryptoSuite::AES128_GCM
                                                    : CryptoSuite::AES256_GCM);
  if (!status_or_bridge_transform_params.ok()) {
    UpdateLatestStatus(status_or_bridge_transform_params.status());
    SetState(State::kSessionError);
    return;
  }
  auto rekey_status =
      datapath_->Rekey(status_or_bridge_transform_params->uplink_key(),
                       status_or_bridge_transform_params->downlink_key());
  if (!rekey_status.ok()) {
    UpdateLatestStatus(rekey_status);
    SetState(State::kSessionError);
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
    SetState(State::kSessionError);
    return;
  }

  if (datapath_ == nullptr) {
    LOG(ERROR) << "No datapath found while rekeying";
    SetState(State::kSessionError);
    return;
  }

  // Session start handling.
  if (!is_rekey) {
    SetState(State::kEgressSessionCreated);
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
  auto new_key_material = absl::make_unique<crypto::SessionCrypto>();
  auto status_or_signature =
      key_material_->GenerateSignature(new_key_material->public_value());
  if (!status_or_signature.ok()) {
    return status_or_signature.status();
  }
  new_key_material->SetSignature(status_or_signature.value());
  key_material_.reset();
  key_material_ = std::move(new_key_material);
  auth_->SetCrypto(key_material_.get());
  auth_->Start(/*is_rekey=*/true);
  return absl::OkStatus();
}

absl::optional<int> Session::active_tun_fd_test_only() const {
  absl::MutexLock l(&mutex_);
  if (active_tunnel_ == nullptr) {
    return absl::nullopt;
  }
  auto status_or_fd = active_tunnel_->GetFd();
  if (!status_or_fd.ok()) {
    return absl::nullopt;
  }
  return status_or_fd.value();
}

void Session::StartDatapath() {
  if (state_ != State::kEgressSessionCreated) {
    LOG(INFO) << "Tunnel FD is updated but not updating the datapath as the "
                 "session is in the wrong state "
              << StateString(state_);
    return;
  }
  auto status_or_egress_response = egress_manager_->GetEgressSessionDetails();
  if (!status_or_egress_response.ok()) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    UpdateLatestStatus(status_or_egress_response.status());
    SetState(State::kSessionError);
    return;
  }

  BridgeTransformParams bridge_transform_params;
  if (config_->bridge_over_ppn()) {
    // Check if the key material is set.
    auto status_or_bridge_transform_params =
        key_material_->GetBridgeTransformParams(
            config_->cipher_suite_key_length() == 128
                ? CryptoSuite::AES128_GCM
                : CryptoSuite::AES256_GCM);
    if (!status_or_bridge_transform_params.ok()) {
      UpdateLatestStatus(status_or_bridge_transform_params.status());
      SetState(State::kSessionError);
      return;
    }
    bridge_transform_params = status_or_bridge_transform_params.value();
  }

  auto datapath_status = datapath_->Start(
      status_or_egress_response.value(), bridge_transform_params,
      config_->cipher_suite_key_length() == 128 ? CryptoSuite::AES128_GCM
                                                : CryptoSuite::AES256_GCM);
  if (!datapath_status.ok()) {
    LOG(ERROR) << "Datapath initialization failed with status:"
               << datapath_status;
    UpdateLatestStatus(datapath_status);
    SetState(State::kSessionError);
    return;
  }
  // Datapath initialized is treated as connected event. In case of failure, we
  // should get a failure from datapath.
  SetState(State::kConnected);

  if (!active_network_info_) {
    LOG(INFO) << "There is no active network info, waiting for SetNetwork";
    return;
  }
  LOG(INFO) << "Active network is available, switching the network";
  auto status = SwitchDatapath();
  if (!status.ok()) {
    LOG(ERROR) << "Switching datapath failed with status" << status;
  }
}

void Session::StartFetchCountersTimer() {
  // Start fetching the counters every 5 mins.
  CancelFetcherTimerIfRunning();
  LOG(INFO) << "Starting FetchCounters timer.";
  auto status_or_timer_id = timer_manager_->StartTimer(
      kFetchTimerDuration, absl::bind_front(&Session::FetchCounters, this));
  if (!status_or_timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for fetch counters";
    return;
  }
  fetch_timer_id_ = status_or_timer_id.value();
}

void Session::StartDatapathReattemptTimer() {
  CancelDatapathReattemptTimerIfRunning();
  LOG(INFO) << "Starting Datapath reattempt timer.";
  auto status_or_timer_id = timer_manager_->StartTimer(
      kDatapathReattemptDuration,
      absl::bind_front(&Session::AttemptDatapathReconnect, this));
  if (!status_or_timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for DatapathReattempt";
    return;
  }

  datapath_reattempt_timer_id_ = status_or_timer_id.value();
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
      (config_->has_rekey_duration()
           ? absl::Seconds(config_->rekey_duration().seconds())
           : kDefaultRekeyDuration)) {
    LOG(INFO) << "Starting Rekey procedures";
    auto status = Rekey();
    if (!status.ok()) {
      LOG(INFO) << "Rekey status " << status;
      SetState(State::kSessionError);
      UpdateLatestStatus(status);
      return;
    }
  }
  StartFetchCountersTimer();
}

absl::optional<NetworkInfo> Session::active_network_info() const {
  absl::MutexLock l(&mutex_);
  return active_network_info_;
}

void Session::EgressUnavailable(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  UpdateLatestStatus(status);
  LOG(ERROR) << "Egress unavailable with status:" << status;
  SetState(State::kSessionError);
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
  datapath_ipv4_attempts_ = 0;
  datapath_ipv6_attempts_ = 0;
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
    // UpdateActiveNetworkInfo(new_network_info);
    auto status = SwitchDatapath();
    if (!status.ok()) {
      LOG(ERROR) << "Switch datapath failed with status:" << status;
    }
}

bool Session::IsFdCurrentActiveFd(int failed_fd) {
  if (!active_network_info_) {
    return false;
  }
  if (!active_network_socket_) {
    return false;
  }
  auto current_fd = active_network_socket_->GetFd();
  if (!current_fd.ok()) {
    return false;
  }
  return current_fd.value() == failed_fd;
}

void Session::DatapathFailed(const absl::Status& status, int failed_fd) {
  absl::MutexLock l(&mutex_);
  if (!IsFdCurrentActiveFd(failed_fd)) {
    LOG(INFO) << "Received event for old FD " << failed_fd;
    return;
  }

  LOG(ERROR) << "Datapath Failed with status:" << status;
  datapath_connected_ = false;
  UpdateLatestDatapathStatus(status);
  // For failures on datapath, see if we can reattempt.
  if ((datapath_reattempt_count_.load() < MAX_DATAPATH_REATTEMPTS) &&
      IsReattemptable(status)) {
    LOG(INFO) << "Datapath failed, waiting to see if it can get reconnected";
    datapath_reattempt_count_.fetch_add(1);
    StartDatapathReattemptTimer();
    return;
  }

  LOG(INFO)
      << "Max reattempts reached on datapath failure, sending notification";
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

void Session::UpdateActiveNetworkInfo(
    absl::optional<NetworkInfo> network_info) {
  // Based on the feedback from Android Eng, underlying network should be the
  // right choice and IsMetered should only be used when VPN itself is charging.
  active_network_info_ = network_info;
}

absl::Status Session::SetNetwork(absl::optional<NetworkInfo> network_info) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Switching network";
  ResetAllDatapathReattempts();

  UpdateActiveNetworkInfo(network_info);

  if (state_ != State::kConnected) {
    LOG(INFO) << "Session is not in connected state, caching active network fd";
    return absl::OkStatus();
  }

  return SwitchDatapath();
}

absl::StatusOr<std::string> Session::SelectDatapathAddress() {
  auto egress_node_sock_addresses =
      egress_manager_->egress_node_sock_addresses();
  if (egress_node_sock_addresses.empty()) {
    return absl::FailedPreconditionError("No Egress node socket address found");
  }

  if (datapath_ipv6_attempts_ < MAX_ATTEMPTS_PER_ADDRESS_FAMILY) {
    auto ip = egress_manager_->EgressNodeV6SocketAddress();
    if (ip) {
      ++datapath_ipv6_attempts_;
      LOG(INFO) << "Attemping datapath on IPv6 " << ip.value()
                << " attempt: " << datapath_ipv6_attempts_.load()
                << " IPv4 attempts:" << datapath_ipv4_attempts_;
      return ip.value();
    }
  }
  if (datapath_ipv4_attempts_ < MAX_ATTEMPTS_PER_ADDRESS_FAMILY) {
    auto ip = egress_manager_->EgressNodeV4SocketAddress();
    if (ip) {
      ++datapath_ipv4_attempts_;
      LOG(INFO) << "Attemping datapath on IPv4 " << ip.value()
                << " attempt: " << datapath_ipv4_attempts_.load()
                << " IPv6 attempts:" << datapath_ipv6_attempts_;
      return ip.value();
    }
  }
  return absl::ResourceExhaustedError(
      "Max reattempts have been reached on both IPv4 and IPv6");
}

absl::Status Session::SwitchDatapath() {
  if (active_network_info_) {
    LOG(INFO) << "Switching Network to network of type "
              << active_network_info_->network_type();
  } else {
    LOG(INFO) << "Removing all networks in SwitchDatapath";
  }

  if (datapath_ == nullptr) {
    UpdateLatestStatus(
        absl::FailedPreconditionError("Datapath is not initialized"));
    return latest_status_;
  }

  auto status_or_egress_response = egress_manager_->GetEgressSessionDetails();
  if (!status_or_egress_response.ok()) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    UpdateLatestStatus(status_or_egress_response.status());
    SetState(State::kSessionError);
    return latest_status_;
  }

  auto tunnel_status = CreateTunnelIfNeeded();
  if (!tunnel_status.ok()) {
    UpdateLatestStatus(tunnel_status);
    LOG(ERROR) << "Tunnel creation failed with status " << tunnel_status;
    SetState(State::kSessionError);
    return tunnel_status;
  }
  LOG(INFO) << "Got tunnel " << active_tunnel_->DebugString();

  // We are creating the network socket after tunnel to see the reduction in
  // PERMISSION_DENIED errors on the socket. This call won't eliminate all the
  // PERMISSION_DENIED errors.
  if (active_network_info_) {
    auto status_or_socket =
        vpn_service_->CreateProtectedNetworkSocket(*active_network_info_);
    if (!status_or_socket.ok()) {
      auto active_network_info_opt = active_network_info_;
      auto* notification = notification_;
      auto status = status_or_socket.status();
      auto network_info = active_network_info_opt
                              ? active_network_info_opt.value()
                              : NetworkInfo();
      notification_thread_->Post([notification, status, network_info] {
        notification->DatapathDisconnected(network_info, status);
      });
      return status_or_socket.status();
    }
    active_network_socket_ = std::move(status_or_socket).value();

    LOG(INFO) << "Network tunnel returned "
              << active_network_socket_->DebugString();
  }

  auto current_restart_counter = network_switches_count_.fetch_add(1);
  if (active_network_info_) {
    LOG(INFO) << "SwitchDatapath Counter " << current_restart_counter
              << " for network type " << active_network_info_->network_type();
  } else {
    LOG(INFO) << "SwitchDatapath removing all networks";
  }

  std::vector<std::string> egress_node_ips;
  PPN_ASSIGN_OR_RETURN(const auto& ip, SelectDatapathAddress());
  egress_node_ips.push_back(ip);

  auto switch_data_status = datapath_->SwitchNetwork(
      egress_manager_->uplink_spi(), egress_node_ips, active_network_info_,
      active_network_socket_.get(), active_tunnel_.get(),
      current_restart_counter);

  return switch_data_status;
}

absl::Status Session::ClearDatapath() {
  LOG(INFO) << "Removing all networks in SwitchDatapath";

  if (datapath_ == nullptr) {
    UpdateLatestStatus(
        absl::FailedPreconditionError("Datapath is not initialized"));
    return latest_status_;
  }

  auto status_or_egress_response = egress_manager_->GetEgressSessionDetails();
  if (!status_or_egress_response.ok()) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    UpdateLatestStatus(status_or_egress_response.status());
    SetState(State::kSessionError);
    return latest_status_;
  }

  auto current_restart_counter = network_switches_count_.fetch_add(1);
  if (!active_tunnel_) {
    return absl::NotFoundError("Tunnel is not set");
  }

  std::vector<std::string> egress_node_ips;
  return datapath_->SwitchNetwork(
      egress_manager_->uplink_spi(), egress_node_ips, absl::nullopt, nullptr,
      active_tunnel_.get(), current_restart_counter);
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
  if (active_tunnel_ != nullptr) {
    auto status_or_fd = active_tunnel_->GetFd();
    if (status_or_fd.ok()) {
      debug_info->set_active_tun_fd(status_or_fd.value());
    }
  }
  if (active_network_info_) {
    debug_info->mutable_active_network()->CopyFrom(
        active_network_info_.value());
  }
  debug_info->set_successful_rekeys(number_of_rekeys_.load());
  auto delta_network_switches =
      network_switches_count_ - last_repoted_network_switches_;
  debug_info->set_network_switches(delta_network_switches);
}

void Session::DoRekey() {
  absl::MutexLock l(&mutex_);
  auto status = Rekey();
  if (!status.ok()) {
    LOG(ERROR) << "Rekey procedure failed";
    UpdateLatestStatus(status);
    SetState(State::kSessionError);
  }
}
}  // namespace krypton
}  // namespace privacy
