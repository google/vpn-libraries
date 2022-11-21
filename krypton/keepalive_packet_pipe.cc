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

#include "privacy/net/krypton/keepalive_packet_pipe.h"

#include <functional>
#include <thread>
#include <utility>
#include <vector>

namespace privacy {
namespace krypton {

absl::Status KeepAlivePacketPipe::StopReadingPackets() {
  {
    absl::MutexLock l(&mutex_);
    if (stopped_) {
      LOG(ERROR)
          << "Stopped_ should be false when StopReadingPackets is called";
    }
    stopped_ = true;
    packet_read_cv_.Signal();
  }
  if (timeout_thread_.joinable()) {
    timeout_thread_.join();
  }
  return packet_pipe_->StopReadingPackets();
}

void KeepAlivePacketPipe::ReadPackets(
    std::function<bool(absl::Status, std::vector<Packet>)> handler) {
  {
    absl::MutexLock l(&mutex_);
    if (stopped_) {
      LOG(ERROR) << "Stopped_ should be false when the pipe starts";
    }
  }
  timeout_thread_ = std::thread([this, handler] {
    mutex_.Lock();
    while (!stopped_) {
      if (packet_read_cv_.WaitWithTimeout(&mutex_, timeout_)) {
        mutex_.Unlock();
        // TODO: Figure out how can we construct the keepalive
        // packet properly.
        handler(absl::OkStatus(), std::vector<Packet>());
        mutex_.Lock();
      }
    }
    mutex_.Unlock();
  });
  packet_pipe_->ReadPackets(
      [this, handler](absl::Status status, std::vector<Packet> packets) {
        {
          absl::MutexLock l(&mutex_);
          packet_read_cv_.Signal();
        }
        return handler(status, std::move(packets));
      });
}

}  // namespace krypton
}  // namespace privacy
