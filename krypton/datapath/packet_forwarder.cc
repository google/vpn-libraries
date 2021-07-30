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

#include "privacy/net/krypton/datapath/packet_forwarder.h"

#include "base/logging.h"
#include "third_party/absl/status/statusor.h"

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
      connected_(false),
      notification_thread_(looper),
      notification_(notification) {}

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
  utun_pipe_->ReadPackets([=](absl::Status status, Packet packet) {
    if (!status.ok()) {
      LOG(ERROR) << "Read device pipe error: " << status;
      auto* notification = notification_;
      notification_thread_->Post([notification, status]() {
        notification->PacketForwarderPermanentFailure(status);
      });
      return false;
    }

    Packet encrypted;
    if (encryptor_ != nullptr) {
      auto encrypted_or = encryptor_->Process(packet);
      if (!encrypted_or.ok()) {
        LOG(WARNING) << "Encryption error status: " << encrypted_or.status();
        auto* notification = notification_;
        auto encryption_status = encrypted_or.status();
        notification_thread_->Post([notification, encryption_status]() {
          notification->PacketForwarderPermanentFailure(encryption_status);
        });
        return false;
      }
      encrypted = std::move(encrypted_or).value();
    } else {
      encrypted = std::move(packet);
    }
    absl::Status write_status = network_pipe_->WritePacket(encrypted);
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
  network_pipe_->ReadPackets([=](absl::Status status, Packet packet) {
    if (!status.ok()) {
      LOG(ERROR) << "Read network pipe error: " << status;
      auto* notification = notification_;
      notification_thread_->Post([notification, status]() {
        notification->PacketForwarderFailed(status);
      });
      return false;
    }

    Packet decrypted;
    if (decryptor_ != nullptr) {
      auto decrypted_or = decryptor_->Process(packet);
      if (!decrypted_or.ok()) {
        LOG(WARNING) << "Decryption error status: " << decrypted_or.status();
        // To avoid DDoS attacks, silently ignore the error and drop the packet.
        return true;
      }
      decrypted = std::move(decrypted_or).value();
    } else {
      decrypted = std::move(packet);
    }

    auto write_status = utun_pipe_->WritePacket(decrypted);
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
      auto* notification = notification_;
      notification_thread_->Post(
          [notification]() { notification->PacketForwarderConnected(); });
    }
    return true;
  });

  LOG(INFO) << "PacketForwarder is started.";
}

void PacketForwarder::PacketForwarder::Stop() {
  {
    absl::MutexLock lock(&mutex_);
    if (shutdown_) {
      LOG(INFO) << "PacketForwarder has already shut down.";
      return;
    }
    LOG(INFO) << "Stopping PacketForwarder";
    shutdown_ = true;
  }
  auto status = utun_pipe_->StopReadingPackets();
  if (!status.ok()) {
    // There's not really any way to recover from a pipe that won't stop
    // reading. And signaling a failure is pointless when the pipe is already
    // being stopped. So just log the error.
    LOG(ERROR) << "Cannot stop reading on tunnel pipe: " << status;
  }
  network_pipe_->Close();

  LOG(INFO) << "PacketForwarder is stopped.";
}

}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
