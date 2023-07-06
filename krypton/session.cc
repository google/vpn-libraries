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

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/common/proto/update_path_info.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/provision.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/network_info.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/log/die_if_null.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

namespace privacy {
namespace krypton {
namespace {

constexpr int kInvalidTimerId = -1;
constexpr absl::Duration kFetchTimerDuration = absl::Minutes(5);
constexpr absl::Duration kDatapathReattemptDuration = absl::Milliseconds(500);
constexpr absl::Duration kDefaultRekeyDuration = absl::Hours(24);

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

Session::Session(const KryptonConfig& config, std::unique_ptr<Auth> auth,
                 std::unique_ptr<EgressManager> egress_manager,
                 std::unique_ptr<DatapathInterface> datapath,
                 VpnServiceInterface* vpn_service, TimerManager* timer_manager,
                 HttpFetcherInterface* http_fetcher,
                 TunnelManagerInterface* tunnel_manager,
                 std::optional<NetworkInfo> network_info,
                 utils::LooperThread* notification_thread)
    : config_(config),
      datapath_(std::move(ABSL_DIE_IF_NULL(datapath))),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)),
      tunnel_manager_(tunnel_manager),
      datapath_address_selector_(config),
      add_egress_response_(std::nullopt),
      uplink_spi_(-1),
      active_network_info_(network_info),
      provision_notification_thread_("Provision Notification Thread"),
      provision_(std::make_unique<Provision>(
          config, std::move(ABSL_DIE_IF_NULL(auth)),
          std::move(ABSL_DIE_IF_NULL(egress_manager)), http_fetcher, this,
          &provision_notification_thread_)) {
  // Register all state machine events to be sent to Session.
  datapath_->RegisterNotificationHandler(this);
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

std::string ProtoToJsonString(
    const ppn::UpdatePathInfoRequest& update_path_info_request) {
  std::string verification_key_encoded;
  std::string mtu_update_signature_encoded;
  absl::Base64Escape(update_path_info_request.verification_key(),
                     &verification_key_encoded);
  absl::Base64Escape(update_path_info_request.mtu_update_signature(),
                     &mtu_update_signature_encoded);

  nlohmann::json json_obj;
  json_obj[JsonKeys::kSessionId] = update_path_info_request.session_id();
  json_obj[JsonKeys::kUplinkMtu] = update_path_info_request.uplink_mtu();
  json_obj[JsonKeys::kDownlinkMtu] = update_path_info_request.downlink_mtu();
  json_obj[JsonKeys::kVerificationKey] = verification_key_encoded;
  json_obj[JsonKeys::kMtuUpdateSignature] = mtu_update_signature_encoded;
  json_obj[JsonKeys::kApnType] = update_path_info_request.apn_type();
  json_obj[JsonKeys::kControlPlaneSockAddr] =
      update_path_info_request.control_plane_sock_addr();
  return utils::JsonToString(json_obj);
}

absl::Status Session::SendUpdatePathInfoRequest() {
  ppn::UpdatePathInfoRequest update_path_info_request;
  update_path_info_request.set_session_id(uplink_spi_);
  update_path_info_request.set_downlink_mtu(downlink_mtu_);
  update_path_info_request.set_apn_type(provision_->GetApnType());
  PPN_ASSIGN_OR_RETURN(auto control_plane_sock_addr,
                       provision_->GetControlPlaneSockaddr());
  update_path_info_request.set_control_plane_sock_addr(control_plane_sock_addr);

  std::string signed_data =
      absl::StrCat("path_info;", update_path_info_request.session_id(), ";",
                   update_path_info_request.uplink_mtu(), ";",
                   update_path_info_request.downlink_mtu());
  PPN_ASSIGN_OR_RETURN(auto signature,
                       provision_->GenerateSignature(signed_data));
  update_path_info_request.set_mtu_update_signature(signature);

  auto request_json_str = ProtoToJsonString(update_path_info_request);

  HttpRequest http_request;
  http_request.set_url(config_.update_path_info_url());
  http_request.set_json_body(request_json_str);

  if (config_.has_api_key()) {
    (*http_request.mutable_headers())["X-Goog-Api-Key"] = config_.api_key();
  }

  http_fetcher_.PostJsonAsync(
      http_request,
      absl::bind_front(&Session::HandleUpdatePathInfoResponse, this));

  return absl::OkStatus();
}

void Session::HandleUpdatePathInfoResponse(const HttpResponse& response) {
  if (response.status().code() == 200) {
    LOG(INFO) << "Updating path info completed successfully.";
  } else {
    auto status = utils::GetStatusForHttpStatus(response.status().code(),
                                                response.status().message());
    absl::MutexLock l(&mutex_);
    SetState(State::kSessionError, status);
  }
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
  provision_->Start();
}

void Session::Stop(bool forceFailOpen) {
  absl::MutexLock l(&mutex_);
  CancelFetcherTimerIfRunning();
  CancelDatapathReattemptTimerIfRunning();
  provision_->Stop();
  datapath_->Stop();
  datapath_ = nullptr;
  tunnel_manager_->DatapathStopped(forceFailOpen);
}

absl::Status Session::BuildTunFdData(TunFdData* tun_fd_data) const {
  if (!add_egress_response_) {
    return absl::FailedPreconditionError(
        "AddEgressResponse is not initialized");
  }
  tun_fd_data->set_is_metered(false);
  if (config_.dynamic_mtu_enabled()) {
    tun_fd_data->set_mtu(tunnel_mtu_);
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

  PPN_ASSIGN_OR_RETURN(auto ppn_info,
                       add_egress_response_->ppn_dataplane_response());

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

absl::Status Session::CreateTunnel() {
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
  auto status = tunnel_manager_->EnsureTunnelIsUp(tun_fd_data);
  has_active_tunnel_ = status.ok();
  return status;
}

absl::Status Session::UpdateTunnelIfNeeded() {
  if (!has_active_tunnel_) {
    return absl::InternalError("No active tunnel to update.");
  }

  return CreateTunnel();
}

absl::Status Session::CreateTunnelIfNeeded() {
  if (has_active_tunnel_) {
    LOG(INFO) << "Not creating tun fd as it's already present";
    return absl::OkStatus();
  }

  return CreateTunnel();
}

void Session::RekeyDatapath() {
  // Do the rekey procedures.
  LOG(INFO) << "Successful response from egress for rekey";
  auto transform_params = provision_->GetTransformParams();
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

void Session::Rekey() {
  if (state_ != State::kConnected) {
    SetState(State::kSessionError,
             absl::FailedPreconditionError(
                 "Session is not in connected state for rekey"));
  }
  provision_->Rekey();
}

void Session::StartDatapath() {
  if (state_ != State::kEgressSessionCreated) {
    LOG(INFO) << "Tunnel FD is updated but not updating the datapath as the "
                 "session is in the wrong state "
              << StateString(state_);
    return;
  }
  if (!add_egress_response_) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    SetState(State::kSessionError, absl::FailedPreconditionError(
                                       "AddEgressResponse is not initialized"));
    return;
  }

  // Check if the key material is set.
  auto transform_params = provision_->GetTransformParams();
  if (!transform_params.ok()) {
    SetState(State::kSessionError, transform_params.status());
    return;
  }

  tunnel_manager_->DatapathStarted();
  auto datapath_status =
      datapath_->Start(*add_egress_response_, *transform_params);
  if (!datapath_status.ok()) {
    LOG(ERROR) << "Datapath initialization failed with status:"
               << datapath_status;
    tunnel_manager_->DatapathStopped(false);
    if (utils::IsPermanentError(datapath_status)) {
      SetState(State::kPermanentError, datapath_status);
      return;
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
      kFetchTimerDuration, absl::bind_front(&Session::FetchCounters, this),
      "FetchCounters");
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
      absl::bind_front(&Session::AttemptDatapathReconnect, this),
      "DatapathReattempt");
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
    Rekey();
  }
  StartFetchCountersTimer();
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
            << egress_node_sock_addresses_.size() << " possible addresses with "
            << (active_network_info_ ? "an active network" : "no network");
  datapath_address_selector_.Reset(egress_node_sock_addresses_,
                                   active_network_info_);
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
    // Do nothing and return as the datapath came up.
    return;
  }

  // Check if there is an active network.
  if (!active_network_info_) {
    NotifyDatapathDisconnected(NetworkInfo(), latest_datapath_status_);
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
  auto network_info =
      active_network_info_ ? active_network_info_.value() : NetworkInfo();
  NotifyDatapathDisconnected(network_info, status);
}

void Session::DatapathPermanentFailure(const absl::Status& status) {
  LOG(ERROR) << "Datapath has permanent failure with status " << status;
  // Send notification to the reconnector that will automatically reconnect the
  // session. Permanent failures have to be terminated and a new session needs
  // to be created.
  NotifyDatapathDisconnected(NetworkInfo(), status);
}

void Session::UpdateActiveNetworkInfo(std::optional<NetworkInfo> network_info) {
  // Based on the feedback from Android Eng, the underlying network should be
  // the right choice and IsMetered should only be used when the VPN itself is
  // charging.
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
  if (!add_egress_response_) {
    LOG(ERROR) << "AddEgress was successful, but could not fetch details";
    auto status =
        absl::FailedPreconditionError("AddEgressResponse is not initialized");
    SetState(State::kSessionError, status);
    return status;
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

  auto ip = datapath_address_selector_.SelectDatapathAddress();
  if (!ip.ok()) {
    LOG(ERROR) << "Failed to select a datapath address: " << ip.status();
    SetState(State::kSessionError, ip.status());
    return ip.status();
  }

  auto switch_data_status = datapath_->SwitchNetwork(
      uplink_spi_, *ip, active_network_info_, current_restart_counter);

  if (!switch_data_status.ok()) {
    LOG(ERROR) << "Switching networks failed: " << switch_data_status;
    auto network_info =
        active_network_info_ ? active_network_info_.value() : NetworkInfo();
    NotifyDatapathDisconnected(network_info, switch_data_status);
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

  provision_->CollectTelemetry(telemetry);
}

void Session::GetDebugInfo(KryptonDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);

  auto* session_debug_info = debug_info->mutable_session();
  session_debug_info->set_state(StateString(state_));
  session_debug_info->set_status(latest_status_.ToString());
  if (active_network_info_) {
    session_debug_info->mutable_active_network()->CopyFrom(
        active_network_info_.value());
  }
  session_debug_info->set_successful_rekeys(number_of_rekeys_.load());
  auto delta_network_switches =
      network_switches_count_ - last_repoted_network_switches_;
  session_debug_info->set_network_switches(delta_network_switches);

  provision_->GetDebugInfo(debug_info);
  datapath_->GetDebugInfo(session_debug_info->mutable_datapath());
}

void Session::DoRekey() {
  absl::MutexLock l(&mutex_);
  Rekey();
}

void Session::DoUplinkMtuUpdate(int uplink_mtu, int tunnel_mtu) {
  absl::MutexLock l(&mutex_);
  if (state_ != State::kConnected) {
    LOG(INFO) << "Ignoring uplink MTU update in unconnected state.";
    return;
  }

  if (tunnel_mtu != tunnel_mtu_) {
    LOG(INFO) << "Updating tunnel MTU from " << tunnel_mtu_ << " to "
              << tunnel_mtu;
    tunnel_mtu_ = tunnel_mtu;
    datapath_->PrepareForTunnelSwitch();
    auto tunnel_status = UpdateTunnelIfNeeded();
    if (!tunnel_status.ok()) {
      LOG(ERROR) << "Tunnel creation for MTU update failed with status "
                 << tunnel_status;
      datapath_->Stop();
      SetState(State::kSessionError, tunnel_status);
      return;
    }
    datapath_->SwitchTunnel();
  }
  if (uplink_mtu != uplink_mtu_) {
    LOG(INFO) << "Updating uplink MTU from " << uplink_mtu_ << " to "
              << uplink_mtu;
    uplink_mtu_ = uplink_mtu;
  }
}

void Session::DoDownlinkMtuUpdate(int downlink_mtu) {
  absl::MutexLock l(&mutex_);
  if (state_ != State::kConnected) {
    LOG(INFO) << "Ignoring downlink MTU update in unconnected state.";
    return;
  }

  if (downlink_mtu != downlink_mtu_) {
    LOG(INFO) << "Updating downlink MTU from " << downlink_mtu_ << " to "
              << downlink_mtu;
    downlink_mtu_ = downlink_mtu;
    PPN_LOG_IF_ERROR(SendUpdatePathInfoRequest());
  }
}

void Session::Provisioned(const AddEgressResponse& egress_response,
                          bool is_rekey) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Establishing PpnDataplane [IPsec | Bridge]";
  // Set the last rekey. This could be the first one where it's initialized or
  // part of the rekey procedures. Rekey is only valid for PpnDataPlane.
  last_rekey_time_ = absl::Now();

  add_egress_response_ = egress_response;
  auto ppn_dataplane = add_egress_response_->ppn_dataplane_response();
  if (ppn_dataplane.ok()) {
    uplink_spi_ = ppn_dataplane->uplink_spi();
  }

  if (datapath_ == nullptr) {
    LOG(ERROR) << "No datapath found while rekeying";
    SetState(State::kSessionError, absl::InternalError("datapath_ == nullptr"));
    return;
  }

  // Session start handling.
  if (!is_rekey) {
    auto* egress_nodes = ppn_dataplane->mutable_egress_point_sock_addr();
    egress_node_sock_addresses_.clear();
    std::copy(egress_nodes->begin(), egress_nodes->end(),
              std::back_inserter(egress_node_sock_addresses_));

    SetState(State::kEgressSessionCreated, absl::OkStatus());
    ResetAllDatapathReattempts();
    StartDatapath();
    return;
  }

  RekeyDatapath();
}

void Session::ProvisioningFailure(absl::Status status, bool permanent) {
  absl::MutexLock l(&mutex_);
  if (permanent) {
    SetState(State::kPermanentError, status);
  } else {
    SetState(State::kSessionError, status);
  }
}

void Session::NotifyDatapathDisconnected(const NetworkInfo& network_info,
                                         const absl::Status& status) {
  tunnel_manager_->DatapathStopped(/*forceFailOpen=*/false);
  auto* notification = notification_;
  notification_thread_->Post([notification, status, network_info] {
    notification->DatapathDisconnected(network_info, status);
  });
}

}  // namespace krypton
}  // namespace privacy
