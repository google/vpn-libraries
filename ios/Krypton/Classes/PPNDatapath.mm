// Copyright 2021 Google LLC
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

#include "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNDatapath.h"

#include <atomic>
#include <memory>
#include <optional>
#include <utility>

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

// Set it as an int instead bool so it's easier to make more retries in the
// future if necessary.
constexpr int kMaxRetries = 1;
constexpr int kInvalidTimerId = -1;
constexpr absl::Duration kDatapathConnectingDuration = absl::Seconds(10);

absl::Status PPNDatapath::Start(const AddEgressResponse& /*egress_response*/,
                                const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  key_material_ = params;
  return absl::OkStatus();
}

void PPNDatapath::Stop() {
  {
    absl::MutexLock l(&mutex_);
    if (health_check_cancelled_ != nullptr) {
      *health_check_cancelled_ = true;
      health_check_cancelled_.reset();
    }
    CancelDatapathConnectingTimerIfRunning();
    CancelHealthCheckTimer();

    datapath_connecting_count_ = 0;

    if (packet_forwarder_ != nullptr) {
      LOG(INFO) << "Stopping packet_forwarder_: " << packet_forwarder_.debugDescription;
      [packet_forwarder_ stop];
      LOG(INFO) << "Resetting packet_forwarder_: " << packet_forwarder_.debugDescription;
      packet_forwarder_ = nil;
    } else {
      LOG(INFO) << "packet_forwarder_ is null when datapath.Stop() is called";
    }
  }

  // Manually call looper_.Join() to help write tests.
  healthcheck_looper_.Stop();
  healthcheck_looper_.Join();
}

absl::Status PPNDatapath::SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                                        std::optional<NetworkInfo> network_info, int /*counter*/) {
  LOG(INFO) << "Switching network";
  if (!network_info) {
    LOG(ERROR) << "network_info is unset";
    return absl::InvalidArgumentError("network_info is unset");
  }

  NEPacketTunnelFlow* packet_tunnel_flow = vpn_service_->GetPacketTunnelFlow();
  if (packet_tunnel_flow == nil) {
    LOG(ERROR) << "packet_tunnel_flow is nil";
    return absl::FailedPreconditionError("packet_tunnel_flow is nil");
  }

  ShutdownPacketForwarder();

  absl::MutexLock l(&mutex_);
  endpoint_ = endpoint;
  network_info_ = network_info;

  // `session_id` is populated using `egress_manager.uplink_spi`:
  // "privacy/net/krypton/session.cc"
  uplink_spi_ = session_id;

  PPN_RETURN_IF_ERROR(CreateNetworkPipeAndStartPacketForwarder());
  StartDatapathConnectingTimer();
  network_switches_since_health_check_++;
  return absl::OkStatus();
}

absl::Status PPNDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  *key_material_ = params;
  // We need to restart the packet forwarder to pick up the new key material.
  PPN_RETURN_IF_ERROR(CreateNetworkPipeAndStartPacketForwarder());
  StartDatapathConnectingTimer();
  return absl::OkStatus();
}

void PPNDatapath::PacketForwarderHasBetterPath(NWUDPSession* session) {
  absl::MutexLock l(&mutex_);
  auto status = StartPacketForwarder(session);
  if (!status.ok()) {
    PacketForwarderFailed(status);
    return;
  }
  StartDatapathConnectingTimer();
}

void PPNDatapath::ShutdownPacketForwarder() {
  absl::MutexLock l(&mutex_);
  CancelDatapathConnectingTimerIfRunning();
  CancelHealthCheckTimer();
  if (health_check_cancelled_ != nullptr) {
    *health_check_cancelled_ = true;
    health_check_cancelled_.reset();
  }
  if (packet_forwarder_ != nullptr) {
    LOG(INFO) << "Shutting down packet forwarder: "
              << packet_forwarder_.debugDescription.UTF8String;
    [packet_forwarder_ stop];
    packet_forwarder_ = nil;
    LOG(INFO) << "Done shutting down packet forwarder.";
  }
}

void PPNDatapath::StartDatapathConnectingTimer() {
  CancelDatapathConnectingTimerIfRunning();
  LOG(INFO) << "Starting DatapathConnecting timer.";
  auto timer_id = timer_manager_->StartTimer(
      kDatapathConnectingDuration,
      absl::bind_front(&PPNDatapath::HandleDatapathConnectingTimeout, this), "DatapathConnecting");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for connecting datapath";
    return;
  }
  datapath_connecting_timer_id_ = *timer_id;
  datapath_connecting_count_++;
}

void PPNDatapath::CancelDatapathConnectingTimerIfRunning() {
  if (datapath_connecting_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(datapath_connecting_timer_id_);
  }
  datapath_connecting_timer_id_ = kInvalidTimerId;
}

absl::Status PPNDatapath::CreateNetworkPipeAndStartPacketForwarder() {
  LOG(INFO) << "Creating UDP session.";
  PPN_ASSIGN_OR_RETURN(auto udp_session,
                       vpn_service_->CreateUDPSession(*network_info_, endpoint_.value()));
  LOG(INFO) << "Created UDP session: " << udp_session.debugDescription.UTF8String;
  if (udp_session == nil) {
    return absl::InternalError("got a nil udp session");
  }
  return StartPacketForwarder(udp_session);
}

absl::Status PPNDatapath::StartPacketForwarder(NWUDPSession* udp_session) {
  if (!key_material_) {
    LOG(ERROR) << "key_material_ is null";
    return absl::FailedPreconditionError("key_material_ is null");
  }
  if (!uplink_spi_) {
    LOG(ERROR) << "uplink_spi_ is not set";
    return absl::FailedPreconditionError("uplink_spi_ is not set");
  }

  PPN_ASSIGN_OR_RETURN(auto encryptor,
                       datapath::ipsec::IpSecEncryptor::Create(*uplink_spi_, *key_material_));
  PPN_ASSIGN_OR_RETURN(auto decryptor, datapath::ipsec::IpSecDecryptor::Create(*key_material_));

  if (packet_forwarder_ != nullptr) {
    LOG(INFO) << "Stopping packet_forwarder_[" << packet_forwarder_ << "].";
    [packet_forwarder_ stop];
    LOG(INFO) << "Resetting packet_forwarder_[" << packet_forwarder_ << "].";
    packet_forwarder_ = nil;
  }

  NEPacketTunnelFlow* packet_tunnel_flow = vpn_service_->GetPacketTunnelFlow();

  LOG(INFO) << "Creating packet forwarder.";
  packet_forwarder_ = [[PPNPacketForwarder alloc] initWithConfig:config_
                                                       encryptor:std::move(encryptor)
                                                       decryptor:std::move(decryptor)
                                                packetTunnelFlow:packet_tunnel_flow
                                                         session:udp_session
                                                    notification:this
                                              notificationLooper:&packet_forwarder_looper_];

  LOG(INFO) << "Starting packet forwarder: " << packet_forwarder_.debugDescription.UTF8String;
  [packet_forwarder_ start];

  return absl::OkStatus();
}

void PPNDatapath::HandleDatapathConnectingTimeout() {
  mutex_.Lock();
  if (datapath_connecting_count_ > kMaxRetries) {
    mutex_.Unlock();
    PacketForwarderFailed(
        absl::DeadlineExceededError("Timeout waiting for datapath to be connected."));
    return;
  }
  PPN_LOG_IF_ERROR(CreateNetworkPipeAndStartPacketForwarder());
  mutex_.Unlock();
}

void PPNDatapath::PacketForwarderFailed(const absl::Status& status) {
  ShutdownPacketForwarder();
  connected_.clear();
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() { notification->DatapathFailed(status); });
}

void PPNDatapath::PacketForwarderPermanentFailure(const absl::Status& status) {
  ShutdownPacketForwarder();
  connected_.clear();
  auto* notification = notification_;
  notification_thread_->Post(
      [notification, status]() { notification->DatapathPermanentFailure(status); });
}

void PPNDatapath::PacketForwarderConnected() {
  if (!connected_.test_and_set()) {
    auto* notification = notification_;
    notification_thread_->Post([notification]() { notification->DatapathEstablished(); });
  }
  if (periodic_health_check_enabled_) {
    StartHealthCheckTimer();
  }
  absl::MutexLock l(&mutex_);
  CancelDatapathConnectingTimerIfRunning();
}

void PPNDatapath::GetDebugInfo(DatapathDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  [packet_forwarder_ collectDebugInfo:debug_info];
  for (const auto& health_check_result : health_check_stats_) {
    *debug_info->add_health_check_results() = health_check_result;
  }
}

void PPNDatapath::StartHealthCheckTimer() {
  absl::MutexLock l(&mutex_);
  if (health_check_cancelled_ != nullptr) {
    *health_check_cancelled_ = true;
    health_check_cancelled_.reset();
  }
  health_check_cancelled_ = std::make_shared<std::atomic_bool>(false);
  CancelHealthCheckTimer();
  LOG(INFO) << "Starting HealthCheck timer.";
  auto timer_id = timer_manager_->StartTimer(
      periodic_health_check_duration_,
      absl::bind_front(&PPNDatapath::HandleHealthCheckTimerExpired, this), "HealthCheck");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for HealthCheck";
    return;
  }
  health_check_timer_id_ = *timer_id;
}

void PPNDatapath::CancelHealthCheckTimer() {
  if (health_check_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(health_check_timer_id_);
  }
  health_check_timer_id_ = kInvalidTimerId;
}

void PPNDatapath::HandleHealthCheckTimerExpired() {
  absl::MutexLock l(&mutex_);
  if (health_check_cancelled_ == nullptr || *health_check_cancelled_) {
    // The timer expired after the check was cancelled.
    return;
  }
  auto health_check_cancelled = health_check_cancelled_;
  healthcheck_looper_.Post([health_check_cancelled, this]() {
    LOG(INFO) << "Starting HealthCheck.";
    auto status = vpn_service_->CheckConnection();
    if (*health_check_cancelled) {
      LOG(INFO) << "HealthCheck timeout occurred after it was cancelled";
      return;
    }
    SaveHealthCheckInfo(status.ok());
    LOG(INFO) << "HealthCheck finished with status: " << status;
    if (status.ok()) {
      StartHealthCheckTimer();
      return;
    }
    PacketForwarderFailed(status);
  });
}

void PPNDatapath::SaveHealthCheckInfo(bool health_check_passed) {
  absl::MutexLock l(&mutex_);

  HealthCheckDebugInfo debug_details;
  debug_details.set_health_check_successful(health_check_passed);
  debug_details.set_network_switches_since_health_check(network_switches_since_health_check_);
  health_check_stats_.push_back(debug_details);
  LOG(INFO) << "Network switches since last HealthCheck: " << network_switches_since_health_check_;
  network_switches_since_health_check_ = 0;
}

}  // namespace krypton
}  // namespace privacy
