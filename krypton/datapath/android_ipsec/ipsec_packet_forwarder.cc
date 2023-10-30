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

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_packet_forwarder.h"

#include <atomic>
#include <utility>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

IpSecPacketForwarder::IpSecPacketForwarder(TunnelInterface* utun_interface,
                                           IpSecSocketInterface* network_socket,
                                           utils::LooperThread* looper,
                                           NotificationInterface* notification,
                                           int forwarder_id)
    : utun_interface_(utun_interface),
      network_socket_(network_socket),
      notification_thread_(looper),
      notification_(notification),
      started_(false),
      shutdown_(false),
      forwarder_id_(forwarder_id),
      uplink_packets_read_(0),
      downlink_packets_read_(0),
      downlink_thread_("IpSecPacketForwarder Downlink Thread"),
      uplink_thread_("IpSecPacketForwarder Uplink Thread") {
  connected_.clear();
}

IpSecPacketForwarder::~IpSecPacketForwarder() {
  if (is_started() && !is_shutdown()) {
    LOG(WARNING) << "Packet forwarder calling Stop in destructor";
    Stop();
  }
}

bool IpSecPacketForwarder::is_started() {
  absl::MutexLock lock(&mutex_);
  return started_;
}

bool IpSecPacketForwarder::is_shutdown() {
  absl::MutexLock lock(&mutex_);
  return shutdown_;
}

void IpSecPacketForwarder::Start() {
  {
    absl::MutexLock lock(&mutex_);
    if (started_) {
      LOG(INFO) << "IpSecPacketForwarder has already started";
      return;
    }
    LOG(INFO) << "Starting IpSecPacketForwarder";
    started_ = true;
  }

  // Uplink Flow.
  uplink_thread_.Post([this]() { HandleUplink(); });

  // Downlink Flow.
  downlink_thread_.Post([this]() { HandleDownlink(); });

  LOG(INFO) << "IpSecPacketForwarder[" << this << "] is started.";
}

void IpSecPacketForwarder::IpSecPacketForwarder::Stop() {
  {
    absl::MutexLock lock(&mutex_);
    if (shutdown_) {
      LOG(INFO) << "IpSecPacketForwarder has already shut down.";
      return;
    }
    LOG(INFO) << "Stopping IpSecPacketForwarder[" << this << "].";
    shutdown_ = true;
  }

  utun_interface_->CancelReadPackets();

  uplink_thread_.Stop();
  uplink_thread_.Join();

  PPN_LOG_IF_ERROR(network_socket_->CancelReadPackets());

  LOG(INFO) << "Finished closing network_socket_[" << network_socket_ << "].";

  downlink_thread_.Stop();
  downlink_thread_.Join();

  LOG(INFO) << "IpSecPacketForwarder[" << this << "] is stopped.";
}

void IpSecPacketForwarder::GetDebugInfo(DatapathDebugInfo* debug_info) {
  debug_info->set_uplink_packets_read(uplink_packets_read_.load());
  debug_info->set_downlink_packets_read(downlink_packets_read_.load());
  network_socket_->GetDebugInfo(debug_info);
}

void IpSecPacketForwarder::HandleDownlink() {
  LOG(INFO) << "Starting downlink packet processing ";

  absl::Cleanup exit_message = [] {
    LOG(INFO) << "Exiting downlink packet processing ";
  };

  while (true) {
    auto packets = network_socket_->ReadPackets();
    if (!packets.ok()) {
      LOG(ERROR) << "Network read failed.";
      PostDatapathFailure(packets.status());
      return;
    }
    if (packets->empty()) {
      LOG(INFO) << "Network socket has been closed";
      return;
    }
    WritePacketsToTun(*std::move(packets));
  }
}

void IpSecPacketForwarder::WritePacketsToTun(std::vector<Packet> packets) {
  downlink_packets_read_ += packets.size();

  auto write_status = utun_interface_->WritePackets(std::move(packets));
  if (!write_status.ok()) {
    LOG(ERROR) << "Write device pipe error: " << write_status;
    auto* notification = notification_;
    auto forwarder_id = forwarder_id_;
    notification_thread_->Post([notification, write_status, forwarder_id]() {
      notification->IpSecPacketForwarderPermanentFailure(write_status,
                                                         forwarder_id);
    });
    return;
  }
  // Start() will only be called once in the entire life of a
  // IpSecPacketForwarder.
  if (!connected_.test_and_set()) {
    LOG(INFO) << "IpSecPacketForwarder[" << this << "] is connected.";
    auto* notification = notification_;
    auto forwarder_id = forwarder_id_;
    notification_thread_->Post([notification, forwarder_id]() {
      notification->IpSecPacketForwarderConnected(forwarder_id);
    });
  }
}

void IpSecPacketForwarder::HandleUplink() {
  LOG(INFO) << "Starting uplink packet processing ";

  absl::Cleanup exit_message = [] {
    LOG(INFO) << "Exiting uplink packet processing ";
  };

  while (true) {
    auto packets = utun_interface_->ReadPackets();
    if (!packets.ok()) {
      LOG(ERROR) << "Tunnel read failed.";
      PostDatapathFailure(packets.status());
      return;
    }
    if (packets->empty()) {
      LOG(INFO) << "Tunnel read has been cancelled";
      return;
    }
    WritePacketsToNetwork(*std::move(packets));
  }
}

void IpSecPacketForwarder::WritePacketsToNetwork(std::vector<Packet> packets) {
  uplink_packets_read_ += packets.size();

  absl::Status write_status = network_socket_->WritePackets(std::move(packets));
  if (!write_status.ok()) {
    LOG(ERROR) << "Network write failed.";
    PostDatapathFailure(write_status);
    return;
  }
}

void IpSecPacketForwarder::PostDatapathFailure(const absl::Status& status) {
  bool expected = false;
  if (!permanent_failure_notification_raised_.compare_exchange_strong(expected,
                                                                      true)) {
    LOG(ERROR) << "Datapath permanent failure [Dedup]:" << status;
    return;
  }

  LOG(ERROR) << "IpSecPacketForwarder permanent failure: " << status;

  auto* notification = notification_;
  auto forwarder_id = forwarder_id_;
  notification_thread_->Post([notification, status, forwarder_id]() {
    notification->IpSecPacketForwarderFailed(status, forwarder_id);
  });
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
