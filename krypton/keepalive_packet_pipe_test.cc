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

#include "privacy/net/krypton/keepalive_packet_pipe.h"

#include <thread>  // NOLINT

#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {

namespace {

class FakePacketPipe : public PacketPipe {
 public:
  explicit FakePacketPipe() {}
  ~FakePacketPipe() override = default;

  void Close() override {}

  /// Resumes the reading after a timeout.
  ///
  /// Test only.
  void ResumeReadingPackets() {
    std::function<bool(absl::Status, Packet)> handler;
    {
      absl::MutexLock l(&mutex_);
      handler = handler_;
    }
    handler(absl::OkStatus(), Packet("foo", 3, IPProtocol::kIPv4, []() {}));
  }

  absl::Status StopReadingPackets() override { return absl::OkStatus(); }

  void ReadPackets(std::function<bool(absl::Status, Packet)> handler) override {
    absl::MutexLock l(&mutex_);
    handler_ = handler;
  }

  absl::Status WritePacket(const Packet&) override { return absl::OkStatus(); }

  absl::StatusOr<int> GetFd() const override {
    return absl::UnimplementedError("Not implemented");
  }

  std::string DebugString() override { return ""; }

 private:
  absl::Mutex mutex_;
  std::function<bool(absl::Status, Packet)> handler_;
};

class KeepAlivePacketPipeTest : public ::testing::Test {
 public:
  FakePacketPipe packet_pipe_;
  KeepAlivePacketPipe keepalive_pipe_ =
      KeepAlivePacketPipe(&packet_pipe_, absl::Milliseconds(100));
};

TEST_F(KeepAlivePacketPipeTest, TestTimeout) {
  absl::Mutex mutex;
  absl::CondVar cv;
  absl::MutexLock l(&mutex);
  keepalive_pipe_.ReadPackets(
      [&cv, &mutex](absl::Status status, Packet packet) {
        EXPECT_OK(status);
        EXPECT_EQ(packet.protocol(), IPProtocol::kUnknown);
        absl::MutexLock l(&mutex);
        cv.Signal();
        return true;
      });
  EXPECT_FALSE(cv.WaitWithTimeout(&mutex, absl::Seconds(1)));
  EXPECT_OK(keepalive_pipe_.StopReadingPackets());
}

TEST_F(KeepAlivePacketPipeTest, TestTimeoutAfterReadingPackets) {
  absl::Mutex mutex;
  absl::CondVar cv;
  absl::MutexLock l(&mutex);
  keepalive_pipe_.ReadPackets(
      [&cv, &mutex](absl::Status status, Packet packet) {
        if (packet.protocol() == IPProtocol::kUnknown) {
          absl::MutexLock l(&mutex);
          cv.Signal();
          return false;
        }
        EXPECT_OK(status);
        EXPECT_EQ(packet.data(), "foo");
        return true;
      });

  EXPECT_FALSE(cv.WaitWithTimeout(&mutex, absl::Seconds(1)));
  EXPECT_OK(keepalive_pipe_.StopReadingPackets());
}

TEST_F(KeepAlivePacketPipeTest, TestCanReadPacketsAfterTimeout) {
  absl::Mutex mutex;
  absl::MutexLock l(&mutex);
  absl::CondVar cv;
  keepalive_pipe_.ReadPackets(
      [&cv, &mutex, this](absl::Status status, Packet packet) {
        if (packet.protocol() == IPProtocol::kUnknown) {
          packet_pipe_.ResumeReadingPackets();
          return true;
        }
        absl::MutexLock l(&mutex);
        cv.Signal();
        EXPECT_OK(status);
        EXPECT_EQ(packet.data(), "foo");
        return true;
      });

  EXPECT_FALSE(cv.WaitWithTimeout(&mutex, absl::Seconds(1)));
  EXPECT_OK(keepalive_pipe_.StopReadingPackets());
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
