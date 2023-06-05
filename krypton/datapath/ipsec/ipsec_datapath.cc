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

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/datapath/packet_forwarder.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

// Set it as an int instead bool so it's easier to make more retries in the
// future if necessary.
constexpr int kMaxRetries = 1;
constexpr int kInvalidTimerId = -1;
constexpr absl::Duration kDatapathConnectingDuration = absl::Seconds(10);

absl::Status IpSecDatapath::Start(const AddEgressResponse& /*egress_response*/,
                                  const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  key_material_ = params;
  return absl::OkStatus();
}

void IpSecDatapath::Stop() {
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
      LOG(INFO) << "Stopping packet_forwarder_[" << packet_forwarder_ << "].";
      packet_forwarder_->Stop();
      LOG(INFO) << "Resetting network_socket_[" << network_socket_ << "].";
      network_socket_.reset();
      LOG(INFO) << "Resetting packet_forwarder_[" << packet_forwarder_ << "].";
      packet_forwarder_.reset();
      LOG(INFO) << "Resetting encryptor_[" << encryptor_ << "].";
      encryptor_.reset();
      LOG(INFO) << "Resetting decryptor_[" << decryptor_ << "].";
      decryptor_.reset();
    } else {
      LOG(INFO) << "packet_forwarder_ is null when datapath.Stop() is called";
    }
  }
  // Manually call looper_.Join() to help write tests.
  looper_.Stop();
  looper_.Join();
}

absl::Status IpSecDatapath::SwitchNetwork(
    uint32_t session_id, const Endpoint& endpoint,
    std::optional<NetworkInfo> network_info, int /*counter*/) {
  LOG(INFO) << "Switching network";
  if (!network_info) {
    LOG(ERROR) << "network_info is unset";
    return absl::InvalidArgumentError("network_info is unset");
  }
  auto tunnel = vpn_service_->GetTunnel();
  if (tunnel == nullptr) {
    LOG(ERROR) << "tunnel is null";
    return absl::InvalidArgumentError("tunnel is null");
  }

  ShutdownPacketForwarder();
  absl::MutexLock l(&mutex_);
  endpoint_ = endpoint;
  network_info_ = network_info;

  if (!key_material_) {
    LOG(ERROR) << "key_material_ is null";
    return absl::InvalidArgumentError("key_material_ is null");
  }
  // `session_id` is populated using `egress_manager.uplink_spi`:
  // "privacy/net/krypton/session.cc"
  if (!uplink_spi_.has_value() || *uplink_spi_ != session_id) {
    uplink_spi_ = session_id;
    PPN_ASSIGN_OR_RETURN(encryptor_,
                         Encryptor::Create(*uplink_spi_, *key_material_));
    PPN_ASSIGN_OR_RETURN(decryptor_, Decryptor::Create(*key_material_));
  }

  tunnel_ = tunnel;
  auto status = CreateNetworkPipeAndStartPacketForwarder();
  if (!status.ok()) {
    // Report connection failures through the notification interface, so that
    // they get handled properly.
    auto* notification = notification_;
    notification_thread_->Post(
        [notification, status]() { notification->DatapathFailed(status); });
    return absl::OkStatus();
  }
  StartDatapathConnectingTimer();
  return absl::OkStatus();
}

absl::Status IpSecDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  *key_material_ = params;
  PPN_ASSIGN_OR_RETURN(encryptor_, Encryptor::Create(*uplink_spi_, params));
  PPN_ASSIGN_OR_RETURN(decryptor_, Decryptor::Create(params));
  return absl::OkStatus();
}

void IpSecDatapath::ShutdownPacketForwarder() {
  absl::MutexLock l(&mutex_);
  CancelDatapathConnectingTimerIfRunning();
  CancelHealthCheckTimer();
  if (health_check_cancelled_ != nullptr) {
    *health_check_cancelled_ = true;
    health_check_cancelled_.reset();
  }
  if (packet_forwarder_ != nullptr) {
    LOG(INFO) << "Shutting down packet forwarder[" << packet_forwarder_
              << "]...";
    packet_forwarder_->Stop();
    packet_forwarder_.reset();
    LOG(INFO) << "Done shutting down packet forwarder[" << packet_forwarder_
              << "].";
  }
}

void IpSecDatapath::StartDatapathConnectingTimer() {
  CancelDatapathConnectingTimerIfRunning();
  LOG(INFO) << "Starting DatapathConnecting timer.";
  auto timer_id = timer_manager_->StartTimer(
      kDatapathConnectingDuration,
      absl::bind_front(&IpSecDatapath::HandleDatapathConnectingTimeout, this),
      "DatapathConnecting");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for connecting datapath";
    return;
  }
  datapath_connecting_timer_id_ = *timer_id;
  datapath_connecting_count_++;
}

void IpSecDatapath::CancelDatapathConnectingTimerIfRunning() {
  if (datapath_connecting_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(datapath_connecting_timer_id_);
  }
  datapath_connecting_timer_id_ = kInvalidTimerId;
}

absl::Status IpSecDatapath::CreateNetworkPipeAndStartPacketForwarder() {
  if (packet_forwarder_ != nullptr) {
    LOG(INFO) << "Stopping packet_forwarder_[" << packet_forwarder_ << "].";
    packet_forwarder_->Stop();
    LOG(INFO) << "Resetting network_socket_[" << network_socket_ << "].";
    network_socket_.reset();
    LOG(INFO) << "Resetting packet_forwarder_[" << packet_forwarder_ << "].";
    packet_forwarder_.reset();
  }
  LOG(INFO) << "Creating network pipe.";
  PPN_ASSIGN_OR_RETURN(network_socket_, vpn_service_->CreateNetworkPipe(
                                            *network_info_, endpoint_.value()));
  LOG(INFO) << "Created network pipe[" << network_socket_ << "].";
  if (network_socket_ == nullptr) {
    return absl::InternalError("got a null network socket");
  }

  LOG(INFO) << "Creating packet forwarder.";
  packet_forwarder_ = std::make_unique<datapath::PacketForwarder>(
      encryptor_.get(), decryptor_.get(), tunnel_, network_socket_.get(),
      notification_thread_, this);
  LOG(INFO) << "Starting packet forwarder[" << packet_forwarder_ << "].";
  packet_forwarder_->Start();
  return absl::OkStatus();
}

void IpSecDatapath::HandleDatapathConnectingTimeout() {
  mutex_.Lock();
  datapath_connecting_timer_id_ = kInvalidTimerId;
  if (datapath_connecting_count_ > kMaxRetries) {
    mutex_.Unlock();
    PacketForwarderFailed(absl::DeadlineExceededError(
        "Timeout waiting for datapath to be connected."));
    return;
  }
  LOG(INFO) << "Datapath connection timed out, recreating...";
  auto status = CreateNetworkPipeAndStartPacketForwarder();
  if (!status.ok()) {
    mutex_.Unlock();
    auto* notification = notification_;
    notification_thread_->Post(
        [notification, status]() { notification->DatapathFailed(status); });
    return;
  }
  StartDatapathConnectingTimer();
  mutex_.Unlock();
}

void IpSecDatapath::PacketForwarderFailed(const absl::Status& status) {
  ShutdownPacketForwarder();
  auto* notification = notification_;
  notification_thread_->Post(
      [notification, status]() { notification->DatapathFailed(status); });
}

void IpSecDatapath::PacketForwarderPermanentFailure(
    const absl::Status& status) {
  ShutdownPacketForwarder();
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathPermanentFailure(status);
  });
}

void IpSecDatapath::PacketForwarderConnected() {
  auto* notification = notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathEstablished(); });
  if (periodic_health_check_enabled_) {
    StartHealthCheckTimer();
  }
  absl::MutexLock l(&mutex_);
  CancelDatapathConnectingTimerIfRunning();
}

void IpSecDatapath::GetDebugInfo(DatapathDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  if (packet_forwarder_ != nullptr) {
    packet_forwarder_->GetDebugInfo(debug_info);
  }
}

void IpSecDatapath::StartHealthCheckTimer() {
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
      absl::bind_front(&IpSecDatapath::HandleHealthCheckTimeout, this),
      "HealthCheck");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Cannot StartTimer for HealthCheck";
    return;
  }
  health_check_timer_id_ = *timer_id;
}

void IpSecDatapath::CancelHealthCheckTimer() {
  if (health_check_timer_id_ != kInvalidTimerId) {
    timer_manager_->CancelTimer(health_check_timer_id_);
  }
  health_check_timer_id_ = kInvalidTimerId;
}

void IpSecDatapath::HandleHealthCheckTimeout() {
  absl::MutexLock l(&mutex_);
  if (health_check_cancelled_ == nullptr || *health_check_cancelled_) {
    // The timer expired after the check was cancelled.
    return;
  }
  auto health_check_cancelled = health_check_cancelled_;
  looper_.Post([health_check_cancelled, this]() {
    LOG(INFO) << "Starting HealthCheck.";
    auto status = vpn_service_->CheckConnection();
    if (*health_check_cancelled) {
      LOG(INFO) << "HealthCheck finished after it's cancelled";
      return;
    }
    LOG(INFO) << "HealthCheck finished with status: " << status;
    if (status.ok()) {
      StartHealthCheckTimer();
      return;
    }
    PacketForwarderFailed(status);
  });
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
