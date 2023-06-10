// Copyright 2022 Google LLC
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

#include "privacy/net/krypton/desktop/windows/datapath/wintun_datapath.h"

#include <memory>
#include <string>
#include <utility>

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/desktop/windows/datapath/wintun_packet_forwarder.h"
#include "privacy/net/krypton/desktop/windows/utils/networking.h"
#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::Status WintunDatapath::Start(const AddEgressResponse& egress_response,
                                   const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Starting WintunDatapath";
  if (!egress_response.ppn_dataplane_response().ok()) {
    return absl::InvalidArgumentError("Invalid ppn_dataplane_response");
  }
  PPN_RETURN_IF_ERROR(wintun_->IsWintunInitialized());

  private_ips_.clear();
  auto ip_ranges = egress_response.ppn_dataplane_response()->user_private_ip();
  for (const auto& ip : ip_ranges) {
    if (ip.has_ipv4_range()) {
      LOG(INFO) << "private IPv4: " << ip.ipv4_range();
      private_ips_.push_back(ip.ipv4_range());
    } else if (ip.has_ipv6_range()) {
      LOG(INFO) << "private IPv6: " << ip.ipv6_range();
      private_ips_.push_back(ip.ipv6_range());
    }
  }

  key_material_ = params;
  return absl::OkStatus();
}

void WintunDatapath::Stop() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Stopping WintunDatapath";
  ShutdownPacketForwarder();
  PPN_LOG_IF_ERROR(wintun_->EndSession());
}

absl::Status WintunDatapath::SwitchNetwork(
    uint32_t session_id, const Endpoint& endpoint,
    std::optional<NetworkInfo> network_info, int /*counter*/) {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Switching network to interface " << network_info->network_id();
  ShutdownPacketForwarder();

  // Start a Wintun session.
  // Wintun should already be initialized and have an adapter.
  LOG(INFO) << "Starting Wintun session";
  PPN_ASSIGN_OR_RETURN(auto luid, wintun_->GetAdapterLUID());
  for (const auto& ip : private_ips_) {
    PPN_ASSIGN_OR_RETURN(auto private_ip,
                         ::privacy::krypton::utils::IPRange::Parse(ip));
    PPN_RETURN_IF_ERROR(utils::SetAdapterLocalAddress(luid, private_ip));
  }
  PPN_RETURN_IF_ERROR(utils::SetInterfaceMtu(luid, 1280));
  PPN_RETURN_IF_ERROR(wintun_->StartSession());

  // Create a network socket bound to the given network interface.
  int active_interface_index = static_cast<int>(network_info->network_id());
  if (endpoint.ip_protocol() == IPProtocol::kIPv4) {
    PPN_ASSIGN_OR_RETURN(auto active_if_addr, utils::GetInterfaceIPv4Address(
                                                  active_interface_index));
    PPN_ASSIGN_OR_RETURN(network_socket_,
                         utils::CreateRioNetworkSocket(active_if_addr, endpoint,
                                                       active_interface_index));
  } else if (endpoint.ip_protocol() == IPProtocol::kIPv6) {
    PPN_ASSIGN_OR_RETURN(auto active_if_addr, utils::GetInterfaceIPv6Address(
                                                  active_interface_index));
    PPN_ASSIGN_OR_RETURN(network_socket_,
                         utils::CreateRioNetworkSocket(active_if_addr, endpoint,
                                                       active_interface_index));
  } else {
    return absl::InternalError("endpoint is neither v4 nor v6: " +
                               endpoint.ToString());
  }

  // Create and start WintunPacketForwarder.
  PPN_ASSIGN_OR_RETURN(auto encryptor, datapath::ipsec::IpSecEncryptor::Create(
                                           session_id, key_material_));
  PPN_ASSIGN_OR_RETURN(auto decryptor,
                       datapath::ipsec::IpSecDecryptor::Create(key_material_));
  packet_forwarder_ = std::make_unique<WintunPacketForwarder>(
      std::move(encryptor), std::move(decryptor), wintun_,
      network_socket_.get(), &packet_forwarder_looper_, this);
  PPN_RETURN_IF_ERROR(packet_forwarder_->Start());
  return absl::OkStatus();
}

absl::Status WintunDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  key_material_ = params;
  return absl::OkStatus();
}

void WintunDatapath::PacketForwarderFailed(const absl::Status& status) {
  absl::MutexLock l(&mutex_);
  if (packet_forwarder_ == nullptr) {
    LOG(INFO) << "Packet forwarder is null";
    return;
  }
  PPN_LOG_IF_ERROR(packet_forwarder_->Stop());
  PPN_LOG_IF_ERROR(wintun_->EndSession());
  connected_.clear();
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathFailed(status);
  });
}

void WintunDatapath::PacketForwarderConnected() {
  absl::MutexLock l(&mutex_);
  if (!connected_.test_and_set()) {
    auto* notification = notification_;
    notification_thread_->Post([notification]() {
      notification->DatapathEstablished();
    });
  }
}

void WintunDatapath::GetDebugInfo(DatapathDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  if (packet_forwarder_ == nullptr) {
    return;
  }
  packet_forwarder_->GetDebugInfo(debug_info);
}

void WintunDatapath::ShutdownPacketForwarder() {
  connected_.clear();
  if (packet_forwarder_ == nullptr) {
    LOG(INFO) << "Packet forwarder is null";
    return;
  }
  LOG(INFO) << "Shutting down packet forwarder";
  PPN_LOG_IF_ERROR(packet_forwarder_->Stop());
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
