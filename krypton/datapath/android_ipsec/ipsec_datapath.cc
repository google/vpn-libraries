// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
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

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_split.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

absl::Status IpSecDatapath::Start(
    std::shared_ptr<AddEgressResponse> /*egress_response*/,
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
  return absl::OkStatus();
}

void IpSecDatapath::Stop() {
  absl::MutexLock l(&mutex_);
  ShutdownPacketForwarder();
}

absl::Status IpSecDatapath::SwitchNetwork(
    uint32_t session_id, const Endpoint& endpoint,
    absl::optional<NetworkInfo> network_info, PacketPipe* tunnel,
    int /*counter*/) {
  absl::MutexLock l(&mutex_);

  if (!network_info) {
    LOG(ERROR) << "network_info is unset";
    return absl::InvalidArgumentError("network_info is unset");
  }
  if (tunnel == nullptr) {
    LOG(ERROR) << "tunnel is null";
    return absl::InvalidArgumentError("tunnel is null");
  }

  // TODO: There may still be error notifications in the
  // LooperThread that will be processed after the packet forwarder has been
  // shut down, which could lead to shutting it down multiple times. We need to
  // either have the forwarder have its own LooperThread or filter events from
  // previous runs.
  ShutdownPacketForwarder();

  if (!key_material_) {
    return absl::FailedPreconditionError("Key Material is not set");
  }
  key_material_->set_uplink_spi(session_id);

  PPN_ASSIGN_OR_RETURN(
      network_pipe_, vpn_service_->CreateNetworkPipe(*network_info, endpoint));
  if (network_pipe_ == nullptr) {
    return absl::InternalError("got a null network socket");
  }
  PPN_ASSIGN_OR_RETURN(int network_fd, network_pipe_->GetFd());

  key_material_->set_network_id(network_info->network_id());
  key_material_->set_network_fd(network_fd);
  key_material_->set_destination_address(endpoint.address());
  key_material_->set_destination_port(endpoint.port());
  if (endpoint.ip_protocol() == IPProtocol::kIPv4) {
    key_material_->set_destination_address_family(NetworkInfo::V4);
  } else if (endpoint.ip_protocol() == IPProtocol::kIPv6) {
    key_material_->set_destination_address_family(NetworkInfo::V6);
  } else {
    return absl::InternalError("unsupported address family for endpoint");
  }
  LOG(INFO) << "Configuring IpsecManager with fd=" << network_fd
            << " network=" << network_info->network_id()
            << " uplink_spi=" << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi()
            << " endpoint=" + endpoint.ToString();

  PPN_RETURN_IF_ERROR(vpn_service_->ConfigureIpSec(key_material_.value()));

  LOG(INFO) << "Done configuring IpSecManager.";

  forwarder_ = absl::make_unique<PacketForwarder>(
      /*encryptor = */ nullptr,
      /*decryptor = */ nullptr, tunnel, network_pipe_.get(),
      notification_thread_, this);

  LOG(INFO) << "Starting packet forwarder.";
  forwarder_->Start();

  return absl::OkStatus();
}

absl::Status IpSecDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);

  if (!params.has_ipsec()) {
    LOG(ERROR) << "Received key material that is not of type IpSec";
    return absl::InvalidArgumentError(
        "Received key material that is not of type IPSEC");
  }
  key_material_ = params.ipsec();
  LOG(INFO) << "SetKeyMaterial for IpSec with uplink_spi="
            << key_material_->uplink_spi()
            << " downlink_spi=" << key_material_->downlink_spi();

  return absl::OkStatus();
}

void IpSecDatapath::ShutdownPacketForwarder() {
  if (forwarder_ != nullptr) {
    LOG(INFO) << "Stopping packet forwarder.";
    forwarder_->Stop();
    forwarder_ = nullptr;
  }
  if (network_pipe_ != nullptr) {
    LOG(INFO) << "Resetting network pipe.";
    network_pipe_->Close();
    network_pipe_ = nullptr;
  }
  LOG(INFO) << "The packet forwarder and network pipe are shut down.";
}

void IpSecDatapath::PacketForwarderFailed(const absl::Status& status) {
  LOG(WARNING) << "IpSecDatapath packet forwarder failed: " << status;
  Stop();
  auto* notification = notification_;
  notification_thread_->Post(
      [notification, status]() { notification->DatapathFailed(status); });
}

void IpSecDatapath::PacketForwarderPermanentFailure(
    const absl::Status& status) {
  LOG(WARNING) << "IpSecDatapath packet forwarder permanently failed: "
               << status;
  Stop();
  auto* notification = notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathPermanentFailure(status);
  });
}

void IpSecDatapath::PacketForwarderConnected() {
  LOG(WARNING) << "IpSecDatapath packet forwarder connected.";
  auto* notification = notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathEstablished(); });
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
