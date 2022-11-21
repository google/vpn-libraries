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

#ifndef PRIVACY_NET_KRYPTON_TEST_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_TEST_PACKET_PIPE_H_

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "privacy/net/krypton/pal/packet_pipe.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {

// A special packet pipe that can be used for testing. Has an ID that can be
// used to check equality, as well as methods for reading and writing packets.
class TestPacketPipe : public PacketPipe {
 public:
  explicit TestPacketPipe(int id) : id_(id) {}
  ~TestPacketPipe() override = default;

  TestPacketPipe(const TestPacketPipe&) = delete;
  TestPacketPipe& operator=(const TestPacketPipe&) = delete;

  absl::Status WritePackets(std::vector<Packet> packet) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  void ReadPackets(
      std::function<bool(absl::Status, std::vector<Packet>)> handler) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<std::function<bool(absl::Status, std::vector<Packet>)>>
  GetReadHandler() ABSL_LOCKS_EXCLUDED(mutex_);

  void Close() override {}

  absl::Status StopReadingPackets() override ABSL_LOCKS_EXCLUDED(mutex_);

  // Returns the ID as the FD, for equality checking.
  absl::StatusOr<int> GetFd() const override { return id_; }

  std::string DebugString() override {
    return absl::StrCat("TestPacketPipe{", id_, "}");
  }

 private:
  int id_;  // An ID to make it easy to test that the given pipe was expected.

  absl::Mutex mutex_;

  // Handler set by read that will be called with any packets that are written.
  std::optional<std::function<bool(absl::Status, std::vector<Packet>)>> handler_
      ABSL_GUARDED_BY(mutex_);

  // Packets that have been written to this pipe.
  std::vector<Packet> outbound_packets_;
};

// Checks that a given PacketPipe has the given file descriptor.
MATCHER_P(PacketPipeHasFd, expected_fd,
          absl::StrCat("packet pipe has fd=", expected_fd)) {
  auto packet_pipe = arg;

  auto fd = packet_pipe->GetFd();
  if (!fd.ok()) {
    return false;
  }

  return *fd == expected_fd;
}

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_TEST_PACKET_PIPE_H_
