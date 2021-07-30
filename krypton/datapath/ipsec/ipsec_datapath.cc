// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/ipsec_datapath.h"

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

absl::Status IpSecDatapath::Start(
    std::shared_ptr<AddEgressResponse> /*egress_response*/,
    const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  key_material_ = params;
  return absl::OkStatus();
}

void IpSecDatapath::Stop() {
  absl::MutexLock l(&mutex_);
  if (packet_forwarder_ != nullptr) {
    packet_forwarder_->Stop();
    packet_forwarder_.reset();
    encryptor_.reset();
    decryptor_.reset();
  }
}

absl::Status IpSecDatapath::SwitchNetwork(
    uint32_t session_id, const Endpoint& endpoint,
    absl::optional<NetworkInfo> network_info, PacketPipe* tunnel,
    int /*counter*/) {
  LOG(INFO) << "Switching network";
  if (!network_info) {
    LOG(ERROR) << "network_info is unset";
    return absl::InvalidArgumentError("network_info is unset");
  }
  if (tunnel == nullptr) {
    LOG(ERROR) << "tunnel is null";
    return absl::InvalidArgumentError("tunnel is null");
  }

  ShutdownPacketForwarder();
  absl::MutexLock l(&mutex_);
  endpoint_ = endpoint;

  if (!key_material_) {
    LOG(ERROR) << "key_material_ is null";
    return absl::InvalidArgumentError("key_material_ is null");
  }
  // `session_id` is populated using `egress_manager.uplink_spi`:
  // "privacy/net/krypton/session.cc"
  if (!uplink_spi_.has_value() || *uplink_spi_ != session_id) {
    uplink_spi_ = session_id;

    auto encryptor = std::make_unique<Encryptor>(*uplink_spi_);
    PPN_RETURN_IF_ERROR(encryptor->Start(*key_material_));
    encryptor_ = std::move(encryptor);

    auto decryptor = std::make_unique<Decryptor>();
    PPN_RETURN_IF_ERROR(decryptor->Start(*key_material_));
    decryptor_ = std::move(decryptor);
  }

  LOG(INFO) << "Creating network pipe.";
  PPN_ASSIGN_OR_RETURN(network_socket_, vpn_service_->CreateNetworkPipe(
                                            *network_info, endpoint));
  if (network_socket_ == nullptr) {
    return absl::InternalError("got a null network socket");
  }

  LOG(INFO) << "Creating packet forwarder.";
  packet_forwarder_ = std::make_unique<datapath::PacketForwarder>(
      encryptor_.get(), decryptor_.get(), tunnel, network_socket_.get(),
      notification_thread_, this);
  LOG(INFO) << "Starting packet forwarder.";
  packet_forwarder_->Start();
  return absl::OkStatus();
}

absl::Status IpSecDatapath::SetKeyMaterials(const TransformParams& params) {
  absl::MutexLock l(&mutex_);
  PPN_RETURN_IF_ERROR(encryptor_->Rekey(params));
  PPN_RETURN_IF_ERROR(decryptor_->Rekey(params));
  return absl::OkStatus();
}

void IpSecDatapath::ShutdownPacketForwarder() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Shutting down packet forwarder...";
  if (packet_forwarder_ != nullptr) {
    packet_forwarder_->Stop();
    packet_forwarder_.reset();
  }
  LOG(INFO) << "Done shutting down packet forwarder.";
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
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
