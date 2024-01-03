// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_packet_forwarder.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

using ::privacy::net::common::proto::PpnDataplaneResponse;

IpSecDatapath::~IpSecDatapath() { Stop(); }

absl::Status IpSecDatapath::Start(const AddEgressResponse& egress_response,
                                  const TransformParams& params) {
  DCHECK(notification_ != nullptr)
      << "Notification needs to be set before calling |Start|";
  if (!params.has_ipsec()) {
    return absl::InvalidArgumentError(
        "IPSec datapath missing transform params");
  }
  absl::MutexLock l(&mutex_);
  key_material_ = params.ipsec();
  LOG(INFO) << "Start IpSec with uplink_spi=" << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi();

  PPN_ASSIGN_OR_RETURN(PpnDataplaneResponse ppn_dataplane,
                       egress_response.ppn_dataplane_response());
  for (const std::string& tcp_mss_sockaddr :
       ppn_dataplane.mss_detection_sock_addr()) {
    PPN_ASSIGN_OR_RETURN(Endpoint endpoint,
                         GetEndpointFromHostPort(tcp_mss_sockaddr));
    if (endpoint.ip_protocol() == IPProtocol::kIPv4) {
      ipv4_tcp_mss_endpoint_ = endpoint;
    } else if (endpoint.ip_protocol() == IPProtocol::kIPv6) {
      ipv6_tcp_mss_endpoint_ = endpoint;
    } else {
      LOG(ERROR) << "Invalid MSS Detection Sock Addr received.";
    }
  }
  if (ppn_dataplane.transport_mode_server_port() != 0) {
    transport_mode_server_port_ = ppn_dataplane.transport_mode_server_port();
  }

  return absl::OkStatus();
}

void IpSecDatapath::Stop() {
  absl::MutexLock l(&mutex_);
  ShutDownIpSecPacketForwarder(/*close_network_socket=*/true);
}

absl::Status IpSecDatapath::SwitchNetwork(uint32_t session_id,
                                          const Endpoint& endpoint,
                                          const NetworkInfo& network_info,
                                          int /*counter*/) {
  absl::MutexLock l(&mutex_);

  LOG(INFO) << "Switching Network";

  ShutDownIpSecPacketForwarder(/*close_network_socket=*/true);

  auto tunnel = vpn_service_->GetTunnel();
  if (!tunnel.ok()) {
    NotifyDatapathPermanentFailure(tunnel.status());
    return absl::OkStatus();
  }
  if (*tunnel == nullptr) {
    NotifyDatapathPermanentFailure(absl::InternalError("tunnel is null"));
    return absl::OkStatus();
  }

  if (!key_material_) {
    return absl::FailedPreconditionError("Key Material is not set");
  }
  key_material_->set_uplink_spi(session_id);

  absl::StatusOr<Endpoint> transport_mode_endpoint;
  if (transport_mode_server_port_.has_value()) {
    if (endpoint.ip_protocol() == IPProtocol::kIPv4) {
      transport_mode_endpoint = GetEndpointFromHostPort(absl::Substitute(
          "$0:$1", endpoint.address(), *transport_mode_server_port_));
    } else {
      transport_mode_endpoint = GetEndpointFromHostPort(absl::Substitute(
          "[$0]:$1", endpoint.address(), *transport_mode_server_port_));
    }
  } else {
    transport_mode_endpoint = endpoint;
  }

  if (!transport_mode_endpoint.ok()) {
    NotifyDatapathPermanentFailure(transport_mode_endpoint.status());
    return absl::OkStatus();
  }

  LOG(INFO) << "IPsec Transport Mode Endpoint: "
            << transport_mode_endpoint->ToString();

  absl::StatusOr<std::unique_ptr<IpSecSocketInterface>> network_socket;
  if (config_.dynamic_mtu_enabled()) {
    std::unique_ptr<MtuTracker> mtu_tracker;
    if (network_info.has_mtu()) {
      mtu_tracker = std::make_unique<MtuTracker>(
          endpoint.ip_protocol(), network_info.mtu(), this, &looper_);
    } else {
      mtu_tracker =
          std::make_unique<MtuTracker>(endpoint.ip_protocol(), this, &looper_);
    }
    auto mss_mtu_detection_endpoint =
        endpoint.ip_protocol() == IPProtocol::kIPv4 ? ipv4_tcp_mss_endpoint_
                                                    : ipv6_tcp_mss_endpoint_;
    network_socket = vpn_service_->CreateProtectedNetworkSocket(
        network_info, *transport_mode_endpoint, mss_mtu_detection_endpoint,
        std::move(mtu_tracker));
  } else {
    network_socket = vpn_service_->CreateProtectedNetworkSocket(
        network_info, *transport_mode_endpoint);
  }

  if (!network_socket.ok()) {
    const absl::Status& status = network_socket.status();
    LOG(ERROR) << "Unable to create network socket: " << status;
    NotifyDatapathFailed(status);
    // Returning OK since failure is handled by preceding notification call
    return absl::OkStatus();
  }

  if (*network_socket == nullptr) {
    return absl::InternalError("got a null network socket");
  }
  int network_fd = (*network_socket)->GetFd();

  key_material_->set_network_id(network_info.network_id());
  key_material_->set_network_fd(network_fd);
  key_material_->set_destination_address(endpoint.address());
  key_material_->set_destination_port(endpoint.port());
  if (endpoint.ip_protocol() == IPProtocol::kIPv4) {
    key_material_->set_destination_address_family(NetworkInfo::V4);
    if (config_.has_ipv4_keepalive_interval()) {
      key_material_->set_keepalive_interval_seconds(
          config_.ipv4_keepalive_interval().seconds());
    }
  } else if (endpoint.ip_protocol() == IPProtocol::kIPv6) {
    key_material_->set_destination_address_family(NetworkInfo::V6);
    if (config_.has_ipv6_keepalive_interval()) {
      key_material_->set_keepalive_interval_seconds(
          config_.ipv6_keepalive_interval().seconds());
    }
  } else {
    return absl::InternalError("unsupported address family for endpoint");
  }
  LOG(INFO) << "Configuring IpSecManager with fd=" << network_fd
            << " network=" << network_info.network_id()
            << " uplink_spi=" << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi()
            << " endpoint=" + endpoint.ToString();

  PPN_RETURN_IF_ERROR(vpn_service_->ConfigureIpSec(*key_material_));

  LOG(INFO) << "Done configuring IpSecManager.";

  network_socket_ = *std::move(network_socket);

  health_check_.IncrementNetworkSwitchCounter();

  // TODO: Make the rekey process smoother for network switches
  // Rekey is not necessary for the initial network switch.
  if (std::exchange(rekey_needed_, true)) {
    LOG(INFO) << "Delaying start of packet forwarder until after rekey.";
    if (!std::exchange(rekey_in_progress_, true)) {
      // Start a rekey because the IPsec sequence number has been reset by the
      // network switch.
      auto notification = notification_;
      notification_thread_->Post([notification]() { notification->DoRekey(); });
    }
  } else {
    forwarder_ = std::make_unique<IpSecPacketForwarder>(
        *tunnel, network_socket_.get(), &looper_, this, ++curr_forwarder_id_);
    LOG(INFO) << "Starting packet forwarder with ID=" << curr_forwarder_id_;
    forwarder_->Start();
  }

  return absl::OkStatus();
}

void IpSecDatapath::PrepareForTunnelSwitch() {
  absl::MutexLock l(&mutex_);
  // Need to check if the packet forwarder is already active before we call
  // ShutDownIpSecPacketForwarder. That method call also clears the
  // tunnel_switch_requires_restart_ flag so we cannot set that flag before.
  bool forwarder_active = forwarder_ != nullptr;
  // Shut down the packet forwarder so it is not actively using the old tunnel.
  ShutDownIpSecPacketForwarder(/*close_network_socket=*/false);
  tunnel_switch_in_progress_ = true;
  tunnel_switch_requires_restart_ = forwarder_active;
}

void IpSecDatapath::SwitchTunnel() {
  absl::MutexLock l(&mutex_);
  if (tunnel_switch_requires_restart_) {
    tunnel_switch_requires_restart_ = false;
    StartUpIpSecPacketForwarder();
  }
  tunnel_switch_in_progress_ = false;
}

absl::Status IpSecDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  rekey_in_progress_ = false;

  if (!params.has_ipsec()) {
    LOG(ERROR) << "Received key material that is not of type IpSec";
    return absl::InvalidArgumentError(
        "Received key material that is not of type IPSEC");
  }

  if (!key_material_.has_value()) {
    LOG(ERROR) << "key_material_ is not set";
    return absl::InternalError("key_material_ is not set");
  }

  // Only overwrite the fields that are updated by the rekey.
  // The Uplink SPI is the session ID so this never changes during the session.
  key_material_->set_downlink_spi(params.ipsec().downlink_spi());
  key_material_->set_uplink_key(params.ipsec().uplink_key());
  key_material_->set_downlink_key(params.ipsec().downlink_key());
  key_material_->set_uplink_salt(params.ipsec().uplink_salt());
  key_material_->set_downlink_salt(params.ipsec().downlink_salt());

  LOG(INFO) << "SetKeyMaterial for IpSec with uplink_spi="
            << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi();

  ShutDownIpSecPacketForwarder(/*close_network_socket=*/false);

  LOG(INFO) << "Configuring IpSecManager with fd="
            << key_material_->network_fd()
            << " network=" << key_material_->network_id()
            << " uplink_spi=" << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi()
            << " destAddr=" << key_material_->destination_address()
            << " destPort=" << key_material_->destination_port();
  PPN_RETURN_IF_ERROR(vpn_service_->ConfigureIpSec(*key_material_));
  LOG(INFO) << "Done configuring IpSecManager.";

  StartUpIpSecPacketForwarder();

  return absl::OkStatus();
}

void IpSecDatapath::StopInternal() {
  ShutDownIpSecPacketForwarder(/*close_network_socket=*/true);
}

void IpSecDatapath::StartUpIpSecPacketForwarder() {
  // If the datapath initiated a rekey we will wait for it to finish before
  // starting the packet forwarder.
  if (rekey_in_progress_) {
    LOG(INFO) << "Delaying start of packet forwarder until after rekey.";
    return;
  }

  absl::StatusOr<TunnelInterface*> tunnel = vpn_service_->GetTunnel();
  if (!tunnel.ok()) {
    NotifyDatapathPermanentFailure(tunnel.status());
    return;
  }
  if (*tunnel == nullptr) {
    NotifyDatapathPermanentFailure(absl::InternalError("tunnel is null"));
    return;
  }
  if (network_socket_ == nullptr) {
    NotifyDatapathPermanentFailure(
        absl::InternalError("network socket is null"));
    return;
  }
  forwarder_ = std::make_unique<IpSecPacketForwarder>(
      *tunnel, network_socket_.get(), &looper_, this, ++curr_forwarder_id_);
  LOG(INFO) << "Starting packet forwarder with ID=" << curr_forwarder_id_;
  forwarder_->Start();
}

void IpSecDatapath::ShutDownIpSecPacketForwarder(bool close_network_socket) {
  tunnel_switch_in_progress_ = false;
  tunnel_switch_requires_restart_ = false;
  if (forwarder_ != nullptr) {
    LOG(INFO) << "Stopping packet forwarder.";
    forwarder_->Stop();
    forwarder_ = nullptr;
  }
  if (close_network_socket) {
    CloseNetworkSocket();
  }
  health_check_.Stop();
  LOG(INFO) << "The packet forwarder is shut down.";
}

void IpSecDatapath::CloseNetworkSocket() {
  if (network_socket_ != nullptr) {
    LOG(INFO) << "Closing network socket.";
    PPN_LOG_IF_ERROR(network_socket_->Close());
    network_socket_ = nullptr;
  }
  LOG(INFO) << "The network socket is closed.";
}

bool IpSecDatapath::IsForwarderNotificationValid(int forwarder_id) {
  // If we get a notification during a tunnel switch we should still handle it.
  if (forwarder_ == nullptr && !tunnel_switch_in_progress_) {
    LOG(WARNING) << "Received notification after packet forwarder closed";
    return false;
  }
  if (forwarder_id != curr_forwarder_id_) {
    LOG(WARNING) << "Received notification with ID=" << forwarder_id
                 << " which does not match current ID=" << curr_forwarder_id_;
    return false;
  }
  return true;
}

void IpSecDatapath::NotifyDatapathFailed(const absl::Status& status) {
  auto* notification = notification_;
  notification_thread_->Post(
      [notification, status]() { notification->DatapathFailed(status); });
}

void IpSecDatapath::NotifyDatapathPermanentFailure(const absl::Status& status) {
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathPermanentFailure(status);
  });
}

void IpSecDatapath::IpSecPacketForwarderFailed(const absl::Status& status,
                                               int packet_forwarder_id) {
  absl::MutexLock l(&mutex_);
  if (!IsForwarderNotificationValid(packet_forwarder_id)) return;
  LOG(WARNING) << "IpSecDatapath packet forwarder failed: " << status;
  StopInternal();
  NotifyDatapathFailed(status);
}

void IpSecDatapath::IpSecPacketForwarderPermanentFailure(
    const absl::Status& status, int packet_forwarder_id) {
  absl::MutexLock l(&mutex_);
  if (!IsForwarderNotificationValid(packet_forwarder_id)) return;
  LOG(WARNING) << "IpSecDatapath packet forwarder permanently failed: "
               << status;
  StopInternal();
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathPermanentFailure(status);
  });
}

void IpSecDatapath::IpSecPacketForwarderConnected(int packet_forwarder_id) {
  absl::MutexLock l(&mutex_);
  if (!IsForwarderNotificationValid(packet_forwarder_id)) return;
  // We do not need to report this event more than once per datapath
  if (datapath_established_) {
    return;
  }
  datapath_established_ = true;
  LOG(WARNING) << "IpSecDatapath packet forwarder connected.";
  health_check_.Start();
  auto* notification = notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathEstablished(); });
}

void IpSecDatapath::UplinkMtuUpdated(int uplink_mtu, int tunnel_mtu) {
  auto* notification = notification_;
  notification_thread_->Post([notification, uplink_mtu, tunnel_mtu]() {
    notification->DoUplinkMtuUpdate(uplink_mtu, tunnel_mtu);
  });
}

void IpSecDatapath::DownlinkMtuUpdated(int downlink_mtu) {
  auto* notification = notification_;
  notification_thread_->Post([notification, downlink_mtu]() {
    notification->DoDownlinkMtuUpdate(downlink_mtu);
  });
}

void IpSecDatapath::HealthCheckFailed(const absl::Status& status) {
  NotifyDatapathFailed(status);
}

void IpSecDatapath::HealthCheckStarting() {
  LOG(INFO) << "HealthCheck is checking for connection.";
  auto* notification = notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathHealthCheckStarting(); });
}

void IpSecDatapath::HealthCheckSucceeded() {
  LOG(INFO) << "HealthCheck passed.";
  auto* notification = notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathHealthCheckSucceeded(); });
}

void IpSecDatapath::GetDebugInfo(DatapathDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  if (forwarder_ != nullptr) {
    forwarder_->GetDebugInfo(debug_info);
  }
  health_check_.GetDebugInfo(debug_info);
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
