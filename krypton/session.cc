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
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/common/proto/ppn_status.proto.h"
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
#include "privacy/net/krypton/utils/time_util.h"
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
constexpr absl::Duration kDatapathReattemptDuration = absl::Milliseconds(500);
constexpr absl::Duration kDefaultRekeyDuration = absl::Hours(24);
constexpr absl::Duration kDefaultDatapathConnectingDuration = absl::Seconds(20);

std::string StateString(Session::State state) {
  switch (state) {
    case Session::State::kInitialized:
      return "kInitialized";
    case Session::State::kEgressSessionCreated:
      return "kEgressSessionCreated";
    case Session::State::kControlPlaneConnected:
      return "kControlPlaneConnected";
    case Session::State::kDataPlaneConnected:
      return "kDataPlaneConnected";
    case Session::State::kStopped:
      return "kStopped";
    case Session::State::kDataPlaneError:
      return "kDataPlaneError";
    case Session::State::kDataPlanePermanentError:
      return "kDataPlanePermanentError";
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

using ::google::protobuf::Duration;

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
      datapath_connecting_timer_enabled_(false),
      datapath_connecting_timer_duration_(kDefaultDatapathConnectingDuration),
      rekey_timer_duration_(kDefaultRekeyDuration),
      vpn_service_(ABSL_DIE_IF_NULL(vpn_service)),
      timer_manager_(ABSL_DIE_IF_NULL(timer_manager)),
      notification_thread_(ABSL_DIE_IF_NULL(notification_thread)),
      tunnel_manager_(tunnel_manager),
      datapath_address_selector_(config),
      add_egress_response_(std::nullopt),
      uplink_spi_(-1),
      active_network_info_(network_info),
      looper_("Session Looper"),
      provision_(std::make_unique<Provision>(
          config, std::move(ABSL_DIE_IF_NULL(auth)),
          std::move(ABSL_DIE_IF_NULL(egress_manager)), http_fetcher, this,
          &looper_)),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher), &looper_) {
  // Register all state machine events to be sent to Session.
  datapath_->RegisterNotificationHandler(this);

  if (config_.has_datapath_connecting_timer_duration()) {
    auto duration =
        utils::DurationFromProto(config_.datapath_connecting_timer_duration());
    if (duration.ok()) {
      datapath_connecting_timer_duration_ = *duration;
    } else {
      LOG(WARNING) << "Failed to parse datapath connecting timer duration: "
                   << duration.status();
    }
  }

  if (config_.datapath_connecting_timer_enabled()) {
    if (datapath_connecting_timer_duration_ > absl::ZeroDuration()) {
      datapath_connecting_timer_enabled_ = true;
      LOG(INFO) << "Datapath connecting timer enabled with duration "
                << datapath_connecting_timer_duration_;
    } else {
      LOG(WARNING) << "Unable to enable datapath connecting timer without "
                      "valid duration.";
    }
  }

  if (config_.has_rekey_duration()) {
    auto duration = utils::DurationFromProto(config_.rekey_duration());
    if (duration.ok()) {
      rekey_timer_duration_ = *duration;
    } else {
      LOG(WARNING) << "Failed to parse rekey duration: " << duration.status();
    }
  }
}

Session::~Session() {
  absl::MutexLock l(&mutex_);
  CancelDatapathReattemptTimerIfRunning();
  CancelRekeyTimerIfRunning();
  CancelDatapathConnectingTimerIfRunning();
}

void Session::CancelRekeyTimerIfRunning() {
  if (rekey_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(rekey_timer_id_);
  }
  rekey_timer_id_ = kInvalidTimerId;
}

void Session::CancelDatapathReattemptTimerIfRunning() {
  if (datapath_reattempt_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(datapath_reattempt_timer_id_);
  }
  datapath_reattempt_timer_id_ = kInvalidTimerId;
}

void Session::CancelDatapathConnectingTimerIfRunning() {
  if (datapath_connecting_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(datapath_connecting_timer_id_);
  }
  datapath_connecting_timer_id_ = kInvalidTimerId;
}

std::string ProtoToJsonString(
    const ppn::UpdatePathInfoRequest& update_path_info_request) {
  std::string mtu_update_signature_encoded;
  absl::Base64Escape(update_path_info_request.mtu_update_signature(),
                     &mtu_update_signature_encoded);

  nlohmann::json json_obj;
  json_obj[JsonKeys::kSessionId] = update_path_info_request.session_id();
  json_obj[JsonKeys::kUplinkMtu] = update_path_info_request.uplink_mtu();
  json_obj[JsonKeys::kDownlinkMtu] = update_path_info_request.downlink_mtu();
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
  // TODO: This creates a race condition with rekey
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
    LOG(ERROR) << "Updating path info failed with status: " << status;
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
    case State::kDataPlaneConnected:
    case State::kStopped:
    case State::kDataPlaneError:
    case State::kDataPlanePermanentError:
      break;
    case State::kControlPlaneConnected:
      notification_thread_->Post(
          [notification] { notification->ControlPlaneConnected(); });
      // Schedule the first rekey
      StartRekeyTimer();
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
  CancelRekeyTimerIfRunning();
  CancelDatapathReattemptTimerIfRunning();
  CancelDatapathConnectingTimerIfRunning();
  provision_->Stop();
  if (datapath_ != nullptr) {
    datapath_->Stop();
    datapath_.reset();
  }
  tunnel_manager_->DatapathStopped(forceFailOpen);
  SetState(State::kStopped, absl::OkStatus());
}

void Session::ForceTunnelUpdate() {
  absl::MutexLock l(&mutex_);
  UpdateTunnelIfNeeded(/*force_tunnel_update=*/true);
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

  if (user_private_ip_.empty()) {
    return absl::InvalidArgumentError("missing user_private_ip_");
  }
  for (const auto& ip : user_private_ip_) {
    PPN_ASSIGN_OR_RETURN(auto proto_ip_range, ToTunFdIpRange(ip));
    *(tun_fd_data->add_tunnel_ip_addresses()) = proto_ip_range;
  }

  return absl::OkStatus();
}

absl::Status Session::CreateTunnel(bool force_tunnel_update) {
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
  return tunnel_manager_->CreateTunnel(tun_fd_data, force_tunnel_update);
}

bool Session::IsTunnelCreationErrorPermanent(const absl::Status& status) {
  ppn::PpnStatusDetails details = utils::GetPpnStatusDetails(status);
  return details.detailed_error_code() ==
         ppn::PpnStatusDetails::VPN_PERMISSION_REVOKED;
}

void Session::UpdateTunnelIfNeeded(bool force_tunnel_update) {
  if (!tunnel_manager_->IsTunnelActive()) {
    LOG(INFO) << "No active tunnel to update";
    return;
  }

  datapath_->PrepareForTunnelSwitch();
  auto tunnel_status = CreateTunnel(force_tunnel_update);
  if (!tunnel_status.ok()) {
    datapath_->Stop();
    if (IsTunnelCreationErrorPermanent(tunnel_status)) {
      SetState(State::kPermanentError, tunnel_status);
    } else {
      SetState(State::kSessionError, tunnel_status);
    }
    return;
  }
  datapath_->SwitchTunnel();
}

absl::Status Session::CreateTunnelIfNeeded() {
  if (tunnel_manager_->IsTunnelActive()) {
    LOG(INFO) << "Not creating tun fd as it's already present";
    return absl::OkStatus();
  }

  return CreateTunnel(/*force_tunnel_update=*/false);
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
  number_of_rekeys_++;
}

void Session::Rekey() {
  if (state_ != State::kControlPlaneConnected &&
      state_ != State::kDataPlaneConnected &&
      state_ != State::kDataPlaneError) {
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
  // Datapath initialized is treated as control-plane connected event. In case
  // of failure later, we should get a failure from datapath.
  SetState(State::kControlPlaneConnected, absl::OkStatus());

  if (!active_network_info_) {
    LOG(INFO) << "There is no active network info, waiting for SetNetwork";
    return;
  }
  LOG(INFO) << "Active network is available, switching the network";
  auto status = ConnectDatapath(*active_network_info_);
  if (!status.ok()) {
    LOG(ERROR) << "Switching datapath failed with status: " << status;
  }
}

void Session::StartRekeyTimer() {
  CancelRekeyTimerIfRunning();
  LOG(INFO) << "Starting Rekey timer.";
  absl::StatusOr<int> timer_id = timer_manager_->StartTimer(
      rekey_timer_duration_,
      absl::bind_front(&Session::HandleRekeyTimerExpiry, this), "Rekey");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for Rekey";
    return;
  }
  rekey_timer_id_ = *timer_id;
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

void Session::StartDatapathConnectingTimer() {
  CancelDatapathConnectingTimerIfRunning();
  LOG(INFO) << "Starting Datapath connecting timer.";
  auto timer_id = timer_manager_->StartTimer(
      datapath_connecting_timer_duration_,
      absl::bind_front(&Session::HandleDatapathConnectingTimeout, this),
      "DatapathConnecting");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for DatapathConnecting";
    return;
  }
  datapath_connecting_timer_id_ = *timer_id;
}

void Session::HandleRekeyTimerExpiry() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Rekey timer expired";
  if (rekey_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Rekey timer is already cancelled";
    return;
  }
  rekey_timer_id_ = kInvalidTimerId;
  LOG(INFO) << "Starting rekey";
  Rekey();
}

void Session::DatapathEstablished() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Datapath is established";
  SetState(State::kDataPlaneConnected, absl::OkStatus());
  if (switching_network_) {
    successful_network_switches_++;
    utils::RecordLatency(network_switch_start_time_, &network_switch_latencies_,
                         "NetworkSwitch");
    switching_network_ = false;
  }
  CancelDatapathConnectingTimerIfRunning();
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
  LOG(INFO) << "Datapath reconnect timer expiry";

  if (datapath_reattempt_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Datapath attempt timer is already cancelled, not doing any "
                 "datapath reconnect.";
    return;
  }
  datapath_reattempt_timer_id_ = kInvalidTimerId;

  // While waiting to reconnect timer, datapath could be established as the
  // network fd is not withdrawn from the datapath.
  if (state_ == State::kDataPlaneConnected) {
    LOG(INFO) << "Datapath is already connected, not reattempting";
    // Do nothing and return as the datapath came up.
    return;
  }

  // Check if there is an active network.
  if (!active_network_info_) {
    NotifyDatapathDisconnected(NetworkInfo(), latest_datapath_status_);
    return;
  }
  auto status = ConnectDatapath(*active_network_info_);
  if (!status.ok()) {
    LOG(ERROR) << "ConnectDatapath failed with status:" << status;
  }
}

void Session::HandleDatapathConnectingTimeout() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Datapath connecting timer expiry.";

  if (datapath_connecting_timer_id_ == kInvalidTimerId) {
    LOG(INFO) << "Datapath connecting timer is already cancelled.";
    return;
  }
  datapath_connecting_timer_id_ = kInvalidTimerId;
  datapath_->Stop();
  HandleDatapathFailure(absl::DeadlineExceededError(
      "Timed out waiting for DatapathEstablished."));
}

void Session::DatapathFailed(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  CancelDatapathConnectingTimerIfRunning();
  HandleDatapathFailure(status);
}

void Session::DatapathPermanentFailure(const absl::Status& status) {
  LOG(ERROR) << "Datapath has permanent failure with status " << status;
  absl::MutexLock l(&mutex_);
  // Send notification to the reconnector that will automatically reconnect
  // the session. Permanent failures have to be terminated and a new session
  // needs to be created.
  NotifyDatapathDisconnected(NetworkInfo(), status);
}

absl::Status Session::SetNetwork(const NetworkInfo& network_info) {
  absl::MutexLock l(&mutex_);
  if (active_network_info_) {
    LOG(INFO) << "Switching network to "
              << utils::NetworkInfoDebugString(network_info);
    switching_network_ = true;
    network_switch_start_time_ = absl::Now();
    network_switches_count_++;
  } else {
    LOG(INFO) << "Setting network to "
              << utils::NetworkInfoDebugString(network_info);
  }
  active_network_info_ = network_info;
  ResetAllDatapathReattempts();

  if (state_ != State::kControlPlaneConnected &&
      state_ != State::kDataPlaneConnected &&
      state_ != State::kDataPlaneError) {
    LOG(INFO) << "Session is not in connected state, caching active network";
    return absl::OkStatus();
  }

  return ConnectDatapath(network_info);
}

absl::Status Session::ConnectDatapath(const NetworkInfo& network_info) {
  // The network_info passed into this method should always be the same as
  // active_network_info_. It's passed into the method like this to enforce that
  // this method should never be called when the active_network_info_ is null.
  LOG(INFO) << "Connecting to network of type " << network_info.network_type();

  NotifyDatapathConnecting();
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
    if (IsTunnelCreationErrorPermanent(tunnel_status)) {
      SetState(State::kPermanentError, tunnel_status);
    } else {
      SetState(State::kSessionError, tunnel_status);
    }
    return tunnel_status;
  }
  LOG(INFO) << "Got tunnel";

  LOG(INFO) << "ConnectDatapath Reattempt Counter " << datapath_reattempt_count_
            << " for network " << network_info.network_type();
  auto ip = datapath_address_selector_.SelectDatapathAddress();
  if (!ip.ok()) {
    LOG(ERROR) << "Failed to select a datapath address: " << ip.status();
    SetState(State::kSessionError, ip.status());
    return ip.status();
  }

  if (datapath_connecting_timer_enabled_) {
    StartDatapathConnectingTimer();
  }

  auto connect_data_status = datapath_->SwitchNetwork(
      uplink_spi_, *ip, network_info, ++datapath_switch_network_counter_);

  if (!connect_data_status.ok()) {
    LOG(ERROR) << "Switching networks failed: " << connect_data_status;
    NotifyDatapathDisconnected(network_info, connect_data_status);
  }

  return connect_data_status;
}

void Session::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);

  telemetry->set_successful_rekeys(std::exchange(number_of_rekeys_, 0));
  telemetry->set_network_switches(std::exchange(network_switches_count_, 0));
  telemetry->set_successful_network_switches(
      std::exchange(successful_network_switches_, 0));
  for (const Duration& latency : network_switch_latencies_) {
    *telemetry->add_network_switch_latency() = latency;
  }
  network_switch_latencies_.clear();

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
  session_debug_info->set_successful_rekeys(number_of_rekeys_);
  session_debug_info->set_network_switches(network_switches_count_);

  provision_->GetDebugInfo(debug_info);
  datapath_->GetDebugInfo(session_debug_info->mutable_datapath());
}

void Session::DoRekey() {
  absl::MutexLock l(&mutex_);
  Rekey();
}

void Session::DoUplinkMtuUpdate(int uplink_mtu, int tunnel_mtu) {
  absl::MutexLock l(&mutex_);
  if (state_ != State::kControlPlaneConnected &&
      state_ != State::kDataPlaneConnected) {
    LOG(INFO) << "Ignoring uplink MTU update in unconnected state.";
    return;
  }

  if (tunnel_mtu != tunnel_mtu_) {
    LOG(INFO) << "Updating tunnel MTU from " << tunnel_mtu_ << " to "
              << tunnel_mtu;
    tunnel_mtu_ = tunnel_mtu;
    LOG(INFO) << "Performing tunnel update";
    UpdateTunnelIfNeeded(/*force_tunnel_update=*/false);
    LOG(INFO) << "Forced tunnel update done";
  }
  if (uplink_mtu != uplink_mtu_) {
    LOG(INFO) << "Updating uplink MTU from " << uplink_mtu_ << " to "
              << uplink_mtu;
    uplink_mtu_ = uplink_mtu;
  }
}

void Session::DoDownlinkMtuUpdate(int downlink_mtu) {
  absl::MutexLock l(&mutex_);
  if (state_ != State::kControlPlaneConnected &&
      state_ != State::kDataPlaneConnected) {
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
    const auto& egress_nodes = ppn_dataplane->egress_point_sock_addr();
    egress_node_sock_addresses_.clear();
    std::copy(egress_nodes.begin(), egress_nodes.end(),
              std::back_inserter(egress_node_sock_addresses_));

    const auto& user_private_ip = ppn_dataplane->user_private_ip();
    user_private_ip_.clear();
    std::copy(user_private_ip.begin(), user_private_ip.end(),
              std::back_inserter(user_private_ip_));

    SetState(State::kEgressSessionCreated, absl::OkStatus());
    ResetAllDatapathReattempts();
    StartDatapath();
    return;
  }

  RekeyDatapath();

  // Schedule the next rekey
  StartRekeyTimer();
}

void Session::ProvisioningFailure(absl::Status status, bool permanent) {
  absl::MutexLock l(&mutex_);
  if (permanent) {
    SetState(State::kPermanentError, status);
  } else {
    SetState(State::kSessionError, status);
  }
}

void Session::HandleDatapathFailure(const absl::Status& status) {
  if (!active_network_info_) {
    // This should generally never happen, as the active network should never
    // go from set to unset.
    LOG(INFO) << "Received event after network info was reset.";
    return;
  }

  LOG(ERROR) << "Datapath Failed with status:" << status;
  SetState(State::kDataPlaneError, status);
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
  NotifyDatapathDisconnected(*active_network_info_, status);
}

void Session::NotifyDatapathDisconnected(const NetworkInfo& network_info,
                                         const absl::Status& status) {
  LOG(ERROR) << "Datapath Disconnected with status: " << status;
  SetState(State::kDataPlanePermanentError, status);
  CancelDatapathConnectingTimerIfRunning();
  if (datapath_ != nullptr) {
    datapath_->Stop();
  }
  tunnel_manager_->DatapathStopped(/*force_fail_open=*/false);
  NotificationInterface* notification = notification_;
  notification_thread_->Post([notification, status, network_info] {
    notification->DatapathDisconnected(network_info, status);
  });
}

void Session::NotifyDatapathConnecting() {
  NotificationInterface* notification = notification_;
  notification_thread_->Post(
      [notification] { notification->DatapathConnecting(); });
}

}  // namespace krypton
}  // namespace privacy
