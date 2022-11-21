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

#include "privacy/net/krypton/test_packet_pipe.h"

#include <cstring>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace privacy {
namespace krypton {

// A utility method to copy a packet, just for tests.
Packet CopyPacket(const Packet& packet) {
  size_t size = packet.data().size();
  char* data = new char[size];
  memcpy(data, packet.data().data(), size);
  return Packet(data, size, packet.protocol(), [data] { delete[] data; });
}

absl::Status TestPacketPipe::WritePackets(std::vector<Packet> packets) {
  absl::MutexLock l(&mutex_);
  for (const auto& packet : packets) {
    outbound_packets_.emplace_back(CopyPacket(packet));
  }
  return absl::OkStatus();
}

absl::StatusOr<std::function<bool(absl::Status, std::vector<Packet>)>>
TestPacketPipe::GetReadHandler() {
  absl::MutexLock l(&mutex_);
  if (!handler_) {
    return absl::InternalError("Tried to get handler before ReadPackets.");
  }
  return *handler_;
}

void TestPacketPipe::ReadPackets(
    std::function<bool(absl::Status, std::vector<Packet>)> handler) {
  absl::MutexLock l(&mutex_);
  if (handler_) {
    LOG(FATAL) << "ReadPackets called on test pipe that's already reading: "
               << DebugString();
  }
  handler_ = handler;
}

absl::Status TestPacketPipe::StopReadingPackets() {
  absl::MutexLock l(&mutex_);
  handler_ = std::nullopt;
  return absl::OkStatus();
}

}  // namespace krypton
}  // namespace privacy
