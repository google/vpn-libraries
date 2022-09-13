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

#include "privacy/net/krypton/datapath/packet_forwarder.h"

#include <atomic>
#include <utility>
#include <vector>

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {

PacketForwarder::PacketForwarder(CryptorInterface* encryptor,
                                 CryptorInterface* decryptor,
                                 PacketPipe* utun_pipe,
                                 PacketPipe* network_pipe,
                                 utils::LooperThread* looper,
                                 NotificationInterface* notification)
    : encryptor_(encryptor),
      decryptor_(decryptor),
      utun_pipe_(utun_pipe),
      network_pipe_(network_pipe),
      started_(false),
      shutdown_(false),
      notification_thread_(looper),
      notification_(notification),
      uplink_packets_read_(0),
      downlink_packets_read_(0),
      uplink_packets_dropped_(0),
      downlink_packets_dropped_(0),
      decryption_errors_(0) {
  connected_.clear();
}

bool PacketForwarder::is_started() {
  absl::MutexLock lock(&mutex_);
  return started_;
}

bool PacketForwarder::is_shutdown() {
  absl::MutexLock lock(&mutex_);
  return shutdown_;
}

void PacketForwarder::Start() {
  {
    absl::MutexLock lock(&mutex_);
    if (started_) {
      LOG(INFO) << "PacketForwarder has already started";
      return;
    }
    LOG(INFO) << "Starting PacketForwarder with tunnel="
              << utun_pipe_->DebugString()
              << ", network=" << network_pipe_->DebugString();
    started_ = true;
  }

  // Uplink Flow.
  utun_pipe_->ReadPackets([=](absl::Status status,
                              std::vector<Packet> packets) {
    if (!status.ok()) {
      LOG(ERROR) << "Read device pipe error: " << status;
      auto* notification = notification_;
      notification_thread_->Post([notification, status]() {
        notification->PacketForwarderPermanentFailure(status);
      });
      return false;
    }

    if (utun_pipe_ == nullptr) {
      LOG(INFO) << "ReadPackets callback is invoked on PacketForwarder[" << this
                << "] when utun_pipe_ is null. encryptor_[" << encryptor_
                << "].";
    }

    uplink_packets_read_++;

    std::vector<Packet> encrypted;
    for (auto& packet : packets) {
      if (encryptor_ != nullptr) {
        auto encrypted_or = encryptor_->Process(packet);
        if (absl::IsResourceExhausted(encrypted_or.status())) {
          // This means we don't have the spare RAM to encrypt any more packets
          // right now, so we'll drop this packet. But this isn't a permanent
          // failure.
          uplink_packets_dropped_++;
          return true;
        }
        if (!encrypted_or.ok()) {
          LOG(WARNING) << "Encryption error status: " << encrypted_or.status();
          auto* notification = notification_;
          const auto& encryption_status = encrypted_or.status();
          notification_thread_->Post([notification, encryption_status]() {
            notification->PacketForwarderPermanentFailure(encryption_status);
          });
          return false;
        }
        encrypted.emplace_back(std::move(encrypted_or).value());
      } else {
        encrypted.emplace_back(std::move(packet));
      }
    }
    absl::Status write_status =
        network_pipe_->WritePackets(std::move(encrypted));
    if (!write_status.ok()) {
      LOG(ERROR) << "Write network pipe error: " << write_status;
      auto* notification = notification_;
      notification_thread_->Post([notification, write_status]() {
        notification->PacketForwarderFailed(write_status);
      });
      return false;
    }
    return true;
  });

  // Downlink Flow.
  network_pipe_->ReadPackets([=](absl::Status status,
                                 std::vector<Packet> packets) {
    if (!status.ok()) {
      LOG(ERROR) << "Read network pipe error: " << status;
      auto* notification = notification_;
      notification_thread_->Post([notification, status]() {
        notification->PacketForwarderFailed(status);
      });
      return false;
    }

    if (network_pipe_ == nullptr) {
      LOG(INFO) << "ReadPackets callback is invoked on PacketForwarder[" << this
                << "] when network_pipe_ is null. decryptor_[" << encryptor_
                << "].";
    }

    downlink_packets_read_++;

    std::vector<Packet> decrypted;
    for (auto& packet : packets) {
      if (decryptor_ != nullptr) {
        auto decrypted_or = decryptor_->Process(packet);
        if (absl::IsResourceExhausted(decrypted_or.status())) {
          // This means we don't have the spare RAM to decrypt any more packets
          // right now, so we'll drop this packet. But this isn't a permanent
          // failure.
          downlink_packets_dropped_++;
          return true;
        }
        if (!decrypted_or.ok()) {
          LOG(WARNING) << "Decryption error status: " << decrypted_or.status();
          // To avoid DDoS attacks, silently ignore the error and drop the
          // packet.
          decryption_errors_++;
          return true;
        }
        decrypted.emplace_back(std::move(decrypted_or).value());
      } else {
        decrypted.emplace_back(std::move(packet));
      }
    }

    auto write_status = utun_pipe_->WritePackets(std::move(decrypted));
    if (!write_status.ok()) {
      LOG(ERROR) << "Write device pipe error: " << write_status;
      auto* notification = notification_;
      notification_thread_->Post([notification, write_status]() {
        notification->PacketForwarderPermanentFailure(write_status);
      });
      return false;
    }
    // Start() will only be called once in the entire life of a PacketForwarder.
    if (!connected_.test_and_set()) {
      LOG(INFO) << "PacketForwarder[" << this << "] is connected.";
      auto* notification = notification_;
      notification_thread_->Post(
          [notification]() { notification->PacketForwarderConnected(); });
    }
    return true;
  });

  LOG(INFO) << "PacketForwarder[" << this << "] is started.";
}

void PacketForwarder::PacketForwarder::Stop() {
  {
    absl::MutexLock lock(&mutex_);
    if (shutdown_) {
      LOG(INFO) << "PacketForwarder has already shut down.";
      return;
    }
    LOG(INFO) << "Stopping PacketForwarder[" << this << "].";
    shutdown_ = true;
  }
  auto status = utun_pipe_->StopReadingPackets();
  if (!status.ok()) {
    // There's not really any way to recover from a pipe that won't stop
    // reading. And signaling a failure is pointless when the pipe is already
    // being stopped. So just log the error.
    LOG(ERROR) << "Cannot stop reading on tunnel pipe: " << status;
  } else {
    LOG(INFO) << "Finished StopReadingPackets on utun_pipe_[" << utun_pipe_
              << "].";
  }

  network_pipe_->Close();
  LOG(INFO) << "Finished closing network_pipe_[" << network_pipe_ << "].";

  LOG(INFO) << "PacketForwarder[" << this << "] is stopped.";
}

void PacketForwarder::GetDebugInfo(DatapathDebugInfo* debug_info) {
  debug_info->set_uplink_packets_read(uplink_packets_read_.load());
  debug_info->set_downlink_packets_read(downlink_packets_read_.load());
  debug_info->set_uplink_packets_dropped(uplink_packets_dropped_.load());
  debug_info->set_downlink_packets_dropped(downlink_packets_dropped_.load());
  debug_info->set_decryption_errors(decryption_errors_.load());

  network_pipe_->GetDebugInfo(debug_info->mutable_network_pipe());
  utun_pipe_->GetDebugInfo(debug_info->mutable_device_pipe());
}

}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
