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

#include "privacy/net/krypton/datapath/ipsec/packet_forwarder.h"

#include <atomic>
#include <functional>
#include <string>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "privacy/net/krypton/datapath/ipsec/cryptor_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

class MockNotification : public PacketForwarder::NotificationInterface {
 public:
  MOCK_METHOD(void, PacketForwarderFailed, (const absl::Status&), (override));
  MOCK_METHOD(void, PacketForwarderPermanentFailure, (const absl::Status&),
              (override));
  MOCK_METHOD(void, PacketForwarderConnected, (), (override));
};

class MockCryptor : public CryptorInterface {
 public:
  MockCryptor() : count_(0), always_fail_(false), fail_on_odd_packets_(false) {}

  absl::StatusOr<Packet> Process(const Packet& /*packet*/) override {
    count_++;
    if (always_fail_) {
      return absl::InternalError("Unable to process");
    }
    if (fail_on_odd_packets_ && count_ % 2 != 0) {
      return absl::InternalError("Unable to process");
    }
    // Since the string is a literal, we don't need to worry about deleting it.
    return Packet("bar", 3, IPProtocol::kIPv4, []() {});
  }

  void set_always_fail(bool always_fail) { always_fail_ = always_fail; }

  void set_fail_on_odd_packets(bool fail_on_odd_packets) {
    fail_on_odd_packets_ = fail_on_odd_packets;
  }

 private:
  int count_;
  bool always_fail_;
  bool fail_on_odd_packets_;
};

class MockPacketPipe : public PacketPipe {
 public:
  explicit MockPacketPipe() : shutdown_(false) {}
  ~MockPacketPipe() override = default;

  const std::vector<Packet>& OutboundPackets() const { return sent_packets_; }

  void Close() override {
    shutdown_ = true;
    packet_thread_.join();
  }

  absl::Status StopReadingPackets() override {
    packet_thread_.join();
    return absl::OkStatus();
  }

  void ReadPackets(
      std::function<bool(absl::Status, std::vector<Packet>)> handler) override {
    // Simulate a non-blocking async API.
    packet_thread_ = std::thread([=] {
      for (int i = 0; i < 100; i++) {
        // Since we're using a string literal, we don't have to worry about
        // freeing it.
        Packet packet("foo", 3, IPProtocol::kIPv4, []() {});
        std::vector<Packet> packets;
        packets.emplace_back(std::move(packet));
        auto success = handler(absl::OkStatus(), std::move(packets));
        if (!success) {
          break;
        }
      }
    });
  }

  absl::Status WritePackets(std::vector<Packet> packets) override {
    for (auto& packet : packets) {
      sent_packets_.emplace_back(std::move(packet));
    }
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
  MockCryptor encryptor;
  MockCryptor decryptor;
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
  MockCryptor encryptor;
  MockCryptor decryptor;
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
  auto encryptor = MockCryptor();
  auto decryptor = MockCryptor();
  decryptor.set_always_fail(true);
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
  auto encryptor = MockCryptor();
  auto decryptor = MockCryptor();
  encryptor.set_always_fail(true);

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

TEST_F(PacketForwarderTest, TestCounters) {
  auto encryptor = MockCryptor();
  auto decryptor = MockCryptor();
  decryptor.set_fail_on_odd_packets(true);
  auto forwarder =
      PacketForwarder(&encryptor, &decryptor, &inbound_pipe_, &outbound_pipe_,
                      &notification_thread_, &notification_);

  ASSERT_EQ(inbound_pipe_.OutboundPackets().size(), 0);

  DatapathDebugInfo debug_info;
  forwarder.GetDebugInfo(&debug_info);
  ASSERT_EQ(0, debug_info.uplink_packets_read());
  ASSERT_EQ(0, debug_info.downlink_packets_read());
  ASSERT_EQ(0, debug_info.decryption_errors());

  forwarder.Start();
  forwarder.Stop();

  EXPECT_EQ(inbound_pipe_.OutboundPackets().size(), 50);
  EXPECT_EQ(outbound_pipe_.OutboundPackets().front().data(), "bar");

  forwarder.GetDebugInfo(&debug_info);
  ASSERT_EQ(100, debug_info.uplink_packets_read());
  ASSERT_EQ(100, debug_info.downlink_packets_read());
  ASSERT_EQ(50, debug_info.decryption_errors());

  notification_thread_.Stop();
  notification_thread_.Join();
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
