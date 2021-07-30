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

#include <atomic>
#include <thread>  // NOLINT
#include <vector>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {

class MockNotification : public PacketForwarder::NotificationInterface {
 public:
  MOCK_METHOD(void, PacketForwarderFailed, (const absl::Status&), (override));
  MOCK_METHOD(void, PacketForwarderPermanentFailure, (const absl::Status&),
              (override));
  MOCK_METHOD(void, PacketForwarderConnected, (), (override));
};

class MockCryptor : public CryptorInterface {
 public:
  explicit MockCryptor(bool simulate_failure)
      : simulate_failure_(simulate_failure) {}

  absl::StatusOr<Packet> Process(const Packet& /*packet*/) override {
    if (simulate_failure_) return absl::InternalError("Unable to process");
    // Since the string is a literal, we don't need to worry about deleting it.
    return Packet("bar", 3, IPProtocol::kIPv4, []() {});
  }

  absl::Status Rekey(const TransformParams& /*params*/) override {
    // no-op
    return absl::OkStatus();
  }

 private:
  bool simulate_failure_;
};

class MockPacketPipe : public PacketPipe {
 public:
  explicit MockPacketPipe() : shutdown_(false) {}
  ~MockPacketPipe() override = default;

  bool IsClosed() { return shutdown_; }

  const std::vector<Packet>& OutboundPackets() const { return sent_packets_; }

  void Close() override {
    shutdown_ = true;
    packet_thread_.join();
  }

  absl::Status StopReadingPackets() override {
    packet_thread_.join();
    return absl::OkStatus();
  }

  void ReadPackets(std::function<bool(absl::Status, Packet)> handler) override {
    // Simulate a non-blocking async API.
    packet_thread_ = std::thread([=] {
      for (int i = 0; i < 100; i++) {
        // Since we're using a string literal, we don't have to worry about
        // freeing it.
        auto success = handler(absl::OkStatus(),
                               Packet("foo", 3, IPProtocol::kIPv4, []() {}));
        if (!success) break;
      }
    });
  }

  absl::Status WritePacket(const Packet& packet) override {
    // To make this test safe if we ever stop using string literals, we make a
    // defensive copy of the packet data to push into the vector.
    int size = packet.data().size();
    char* data = static_cast<char*>(malloc(packet.data().length()));
    memcpy(data, packet.data().data(), size);
    Packet copy(data, size, packet.protocol(), [data]() { free(data); });
    sent_packets_.emplace_back(std::move(copy));
    return absl::OkStatus();
  }

  absl::StatusOr<int> GetFd() const override {
    return absl::UnimplementedError("Not implemented");
  }

  std::string DebugString() override { return ""; }

 private:
  std::atomic_bool shutdown_;
  std::vector<Packet> sent_packets_;
  std::thread packet_thread_;
};

class PacketForwarderTest : public ::testing::Test {
 public:
  MockPacketPipe inbound_pipe_ = MockPacketPipe();
  MockPacketPipe outbound_pipe_ = MockPacketPipe();
  utils::LooperThread notification_thread_{"PacketForwarder Test"};
  MockNotification notification_;
};

TEST_F(PacketForwarderTest, TestStartAndStop) {
  auto encryptor = MockCryptor(false);
  auto decryptor = MockCryptor(false);
  auto forwarder =
      PacketForwarder(&encryptor, &decryptor, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  EXPECT_FALSE(forwarder.is_started());
  EXPECT_FALSE(forwarder.is_shutdown());
  forwarder.Start();
  EXPECT_TRUE(forwarder.is_started());
  EXPECT_FALSE(forwarder.is_shutdown());
  forwarder.Stop();
  EXPECT_TRUE(forwarder.is_started());
  EXPECT_TRUE(forwarder.is_shutdown());

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(PacketForwarderTest, TestPacketsAreHandledCorrectly) {
  auto encryptor = MockCryptor(false);
  auto decryptor = MockCryptor(false);
  auto forwarder =
      PacketForwarder(&encryptor, &decryptor, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  EXPECT_CALL(notification_, PacketForwarderConnected()).Times(1);

  ASSERT_EQ(inbound_pipe_.OutboundPackets().size(), 0);
  forwarder.Start();

  forwarder.Stop();

  EXPECT_EQ(inbound_pipe_.OutboundPackets().size(), 100);
  EXPECT_EQ(outbound_pipe_.OutboundPackets().front().data(), "bar");

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(PacketForwarderTest, TestNoCryptors) {
  auto forwarder =
      PacketForwarder(nullptr, nullptr, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  ASSERT_EQ(inbound_pipe_.OutboundPackets().size(), 0);
  forwarder.Start();

  forwarder.Stop();

  EXPECT_EQ(inbound_pipe_.OutboundPackets().size(), 100);
  EXPECT_EQ(outbound_pipe_.OutboundPackets().front().data(), "foo");

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(PacketForwarderTest, TestDecryptionErrorsAreSilentIgnored) {
  auto encryptor = MockCryptor(false);
  auto decryptor = MockCryptor(true);
  auto forwarder =
      PacketForwarder(&encryptor, &decryptor, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  ASSERT_EQ(inbound_pipe_.OutboundPackets().size(), 0);
  forwarder.Start();

  forwarder.Stop();

  EXPECT_EQ(inbound_pipe_.OutboundPackets().size(), 0);

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(PacketForwarderTest, TestEncryptionErrorTriggersPermanentFailure) {
  auto encryptor = MockCryptor(true);
  auto decryptor = MockCryptor(false);

  EXPECT_CALL(notification_, PacketForwarderPermanentFailure(testing::_))
      .Times(1);

  auto forwarder =
      PacketForwarder(&encryptor, &decryptor, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  forwarder.Start();
  forwarder.Stop();
  notification_thread_.Stop();
  notification_thread_.Join();
}

}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
