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

#include "privacy/net/krypton/desktop/windows/datapath/wintun_packet_forwarder.h"

#include <windows.h>
#include <winsock2.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/socket_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

constexpr int kAllocatedPacketSize = 1500;

}

WintunPacketForwarder::WintunPacketForwarder(
    std::unique_ptr<datapath::ipsec::IpSecEncryptor> encryptor,
    std::unique_ptr<datapath::ipsec::IpSecDecryptor> decryptor, Wintun* wintun,
    SocketInterface* socket, ::privacy::krypton::utils::LooperThread* looper,
    WintunPacketForwarder::WintunNotificationInterface* notification)
    : encryptor_(std::move(encryptor)),
      decryptor_(std::move(decryptor)),
      wintun_(wintun),
      socket_(socket),
      notification_thread_(looper),
      notification_(notification),
      uplink_looper_("WintunPacketForwarder Uplink"),
      downlink_looper_("WintunPacketForwarder Downlink"),
      uplink_packets_read_(0),
      downlink_packets_read_(0),
      downlink_packets_dropped_(0),
      decryption_errors_(0),
      tunnel_write_errors_(0) {}

absl::Status WintunPacketForwarder::Start() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Starting WintunPacketForwarder";
  connected_ = false;
  stopped_ = false;

  // Create WintunTunnel.
  tunnel_ = std::make_unique<WintunTunnel>(wintun_);
  PPN_RETURN_IF_ERROR(tunnel_->Start());

  // Start downlink thread.
  downlink_looper_.Post([this]() { ProcessDownlink(); });

  // Start uplink thread.
  uplink_looper_.Post([this]() { ProcessUplink(); });

  return absl::OkStatus();
}

absl::Status WintunPacketForwarder::Stop() {
  absl::MutexLock l(&mutex_);
  // Stop work on threads.
  stopped_ = true;
  // Stop reading packets.
  PPN_RETURN_IF_ERROR(tunnel_->StopReadingPackets());
  PPN_RETURN_IF_ERROR(socket_->Close());
  return absl::OkStatus();
}

void WintunPacketForwarder::GetDebugInfo(DatapathDebugInfo* debug_info) {
  debug_info->set_uplink_packets_read(uplink_packets_read_);
  debug_info->set_downlink_packets_read(downlink_packets_read_);
  // Socket will populate uplink_packets_dropped.
  socket_->GetDebugInfo(debug_info);
  debug_info->set_downlink_packets_dropped(downlink_packets_dropped_);
  debug_info->set_decryption_errors(decryption_errors_);
  debug_info->set_tunnel_write_errors(tunnel_write_errors_);
}

// ProcessUplink should run in a separate thread.
void WintunPacketForwarder::ProcessUplink() {
  while (true) {
    {
      absl::MutexLock l(&mutex_);
      if (stopped_) {
        break;
      }
    }
    // Read packet from the Wintun tunnel.
    auto clear_pkts = tunnel_->ReadPackets();
    if (!clear_pkts.ok()) {
      LOG(WARNING) << "WintunTunnel::ReadPackets failed: "
                   << clear_pkts.status();
      FailWithStatus(clear_pkts.status());
      break;
    }
    uplink_packets_read_ += clear_pkts->size();

    // Encrypt packets.
    std::vector<Packet> enc_pkts;
    for (auto& pkt : *clear_pkts) {
      datapath::ipsec::IpSecPacket enc_pkt;
      auto status =
          encryptor_->Encrypt(pkt.data(), IPProtocol::kUnknown, &enc_pkt);
      if (!status.ok()) {
        LOG(WARNING) << "Encryptor failed: " << status;
        FailWithStatus(status);
        break;
      }
      enc_pkts.emplace_back(const_cast<const char*>(enc_pkt.buffer()),
                            enc_pkt.buffer_size(), IPProtocol::kUnknown,
                            [] {});
    }
    // Send packets via network socket.
    auto result = socket_->WritePackets(std::move(enc_pkts));
    if (!result.ok()) {
      FailWithStatus(result);
      break;
    }

    // Release the received packet buffers.
    for (auto& pkt : *clear_pkts) {
      auto status = wintun_->ReleaseReceivePacket(std::move(pkt));
      if (!status.ok()) {
        LOG(ERROR) << "Wintun::ReleaseReceivePacket failed: " << status;
      }
    }
  }
}

// ProcessDownlink should run in a separate thread.
void WintunPacketForwarder::ProcessDownlink() {
  while (true) {
    {
      absl::MutexLock l(&mutex_);
      if (stopped_) {
        break;
      }
    }
    // Read packets from socket.
    auto enc_pkts = socket_->ReadPackets();
    if (!enc_pkts.ok()) {
      LOG(ERROR) << "Socket::ReadPackets failed: " << enc_pkts.status();
      FailWithStatus(enc_pkts.status());
      return;
    }
    downlink_packets_read_ += enc_pkts->size();
    {
      absl::MutexLock l(&mutex_);
      if (stopped_) {
        return;
      }
      if (!connected_) {
        connected_ = true;
        auto notification = notification_;
        notification_thread_->Post(
            [notification] { notification->PacketForwarderConnected(); });
      }
    }

    std::vector<Packet> decrypted_pkts;
    for (auto& pkt : *enc_pkts) {
      // Allocate temporary buffer for decrypted packet.
      uint8_t temp_buffer[kAllocatedPacketSize];

      // Decrypt packet.
      size_t actual_output_size;
      IPProtocol output_protocol;
      auto status = decryptor_->Decrypt(
          pkt.data(), temp_buffer,
          kAllocatedPacketSize, &actual_output_size, &output_protocol);
      if (!status.ok()) {
        LOG(WARNING) << "Decryptor failed: " << status;
        decryption_errors_++;
        continue;
      }

      status = wintun_->AllocateAndSendPacket(temp_buffer, actual_output_size);
      if (!status.ok()) {
        LOG(WARNING) << "AllocateAndSendPacket failed: " << status;
        tunnel_write_errors_++;
        FailWithStatus(status);
        return;
      }
    }
  }
}

void WintunPacketForwarder::FailWithStatus(absl::Status status) {
  absl::MutexLock l(&mutex_);
  if (stopped_) {
    return;
  }
  stopped_ = true;

  LOG(ERROR) << "WintunPacketForwarder failed with status: " << status;

  auto notification = notification_;
  notification_thread_->Post(
      [notification, status] { notification->PacketForwarderFailed(status); });
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
