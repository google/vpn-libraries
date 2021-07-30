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

#ifndef PRIVACY_NET_KRYPTON_KEEPALIVE_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_KEEPALIVE_PACKET_PIPE_H_

#include <thread>  // NOLINT

#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

/// PacketPipe that will automatically read an empty keepalive packet when no
/// packets have been read in a given duration.
class KeepAlivePacketPipe : public PacketPipe {
 public:
  explicit KeepAlivePacketPipe(PacketPipe* packet_pipe,
                               const absl::Duration timeout)
      : packet_pipe_(packet_pipe), timeout_(timeout) {}

  absl::Status WritePacket(const Packet& packet) override {
    return packet_pipe_->WritePacket(packet);
  }

  void ReadPackets(
      std::function<bool(absl::Status status, Packet packet)> handler) override;

  /// Stops reading packets from the client side tunnel.
  ///
  /// Client side tunnel is not managed by this class, therefore cannot be
  /// closed by this class. Calling this method means the packet pipe should be
  /// discarded and no more calls should be made to `ReadPackets` and
  /// `WritePacket`.
  absl::Status StopReadingPackets() override;

  void Close() override { packet_pipe_->Close(); }

  absl::StatusOr<int> GetFd() const override {
    return absl::UnimplementedError(
        "Fd packet pipe cannot have a keepalive timeout.");
  }

  std::string DebugString() override {
    return absl::StrCat("KeepAlivePacketPipe{", packet_pipe_->DebugString(),
                        ", timeout=", absl::FormatDuration(timeout_), "}");
  }

 private:
  PacketPipe* packet_pipe_;
  absl::Duration timeout_;
  absl::CondVar packet_read_cv_;
  absl::Mutex mutex_;
  bool stopped_ = false;
  std::thread timeout_thread_;

  // Disallow copy and assign.
  KeepAlivePacketPipe(const KeepAlivePacketPipe& other) = delete;
  KeepAlivePacketPipe& operator=(const KeepAlivePacketPipe& other) = delete;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_KEEPALIVE_PACKET_PIPE_H_
