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

#include <utility>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/mock_ipsec_socket.h"
#include "privacy/net/krypton/datapath/android_ipsec/mock_tunnel.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

class MockNotification : public IpSecPacketForwarder::NotificationInterface {
 public:
  MOCK_METHOD(void, IpSecPacketForwarderFailed, (const absl::Status&, int),
              (override));
  MOCK_METHOD(void, IpSecPacketForwarderPermanentFailure,
              (const absl::Status&, int), (override));
  MOCK_METHOD(void, IpSecPacketForwarderConnected, (int), (override));
};

class IpSecPacketForwarderTest : public ::testing::Test {
 public:
  MockTunnel utun_interface_;
  MockIpSecSocket network_socket_;
  utils::LooperThread notification_thread_{"IpSecPacketForwarder Test"};
  MockNotification notification_;
};

TEST_F(IpSecPacketForwarderTest, TestStartAndStop) {
  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Notification network_closed;
  absl::Notification utun_closed;

  EXPECT_CALL(network_socket_, ReadPackets()).WillOnce([&network_closed]() {
    network_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, ReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(network_socket_, Close()).Times(0);

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

TEST_F(IpSecPacketForwarderTest, TestDownlinkPacketHandling) {
  int packet_count = 100;
  const char* test_data = "foo";

  int data_size = strlen(test_data);

  std::vector<Packet> packets;
  for (int i = 0; i < packet_count; ++i) {
    char* data = new char[strlen(test_data)];
    memcpy(data, test_data, data_size);
    packets.emplace_back(data, data_size, IPProtocol::kIPv6,
                         [data] { delete[] data; });
  }

  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Notification connected;
  absl::Notification network_closed;
  absl::Notification utun_closed;

  EXPECT_CALL(notification_,
              IpSecPacketForwarderConnected(/*forwarder_id=*/123))
      .WillOnce([&connected]() { connected.Notify(); });

  EXPECT_CALL(network_socket_, ReadPackets())
      .WillOnce(testing::Return(std::move(packets)))
      .WillOnce([&network_closed]() {
        network_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, WritePackets(testing::_))
      .WillOnce([&packet_count, &test_data](std::vector<Packet> packets) {
        EXPECT_EQ(packets.size(), packet_count);
        if (!packets.empty()) {
          EXPECT_EQ(packets.front().data(), test_data);
          EXPECT_EQ(packets.back().data(), test_data);
        }
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, ReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(network_socket_, Close()).Times(0);

  forwarder.Start();

  EXPECT_TRUE(
      connected.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  DatapathDebugInfo debug_info;
  forwarder.GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.downlink_packets_read(), packet_count);

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(IpSecPacketForwarderTest, TestUplinkPacketHandling) {
  int packet_count = 100;
  const char* test_data = "foo";

  int data_size = strlen(test_data);

  std::vector<Packet> packets;
  for (int i = 0; i < packet_count; ++i) {
    char* data = new char[strlen(test_data)];
    memcpy(data, test_data, data_size);
    packets.emplace_back(data, data_size, IPProtocol::kIPv6,
                         [data] { delete[] data; });
  }

  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Notification connected;
  absl::Notification network_closed;
  absl::Notification utun_closed;

  EXPECT_CALL(network_socket_, WritePackets(testing::_))
      .WillOnce([&packet_count, &test_data](std::vector<Packet> packets) {
        EXPECT_EQ(packets.size(), packet_count);
        if (!packets.empty()) {
          EXPECT_EQ(packets.front().data(), test_data);
          EXPECT_EQ(packets.back().data(), test_data);
        }
        return absl::OkStatus();
      });

  EXPECT_CALL(network_socket_, ReadPackets()).WillOnce([&network_closed]() {
    network_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, ReadPackets())
      .WillOnce(testing::Return(std::exchange(packets, {})))
      .WillOnce([&utun_closed, &connected]() {
        connected.Notify();
        utun_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(network_socket_, Close()).Times(0);

  forwarder.Start();

  EXPECT_TRUE(
      connected.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  DatapathDebugInfo debug_info;
  forwarder.GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.uplink_packets_read(), packet_count);

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(IpSecPacketForwarderTest, TestNetworkWriteFail) {
  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Status write_status = absl::InternalError("Error writing to socket");

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});

  absl::Notification failed;
  absl::Notification network_closed;
  absl::Notification utun_closed;

  EXPECT_CALL(network_socket_, WritePackets(testing::_))
      .WillOnce(testing::Return(write_status));

  EXPECT_CALL(network_socket_, ReadPackets()).WillOnce([&network_closed]() {
    network_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, ReadPackets())
      .WillOnce(testing::Return(std::move(packets)))
      .WillOnce([&utun_closed]() {
        utun_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(notification_,
              IpSecPacketForwarderFailed(write_status, /*forwarder_id=*/123))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_CALL(network_socket_, Close()).Times(0);

  forwarder.Start();

  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(IpSecPacketForwarderTest, TestNetworkReadFail) {
  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Status read_status = absl::InternalError("Error reading from socket");

  absl::Notification failed;
  absl::Notification utun_closed;

  EXPECT_CALL(network_socket_, ReadPackets())
      .WillOnce(testing::Return(read_status));

  EXPECT_CALL(utun_interface_, ReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(notification_,
              IpSecPacketForwarderFailed(read_status, /*forwarder_id=*/123))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_CALL(network_socket_, Close()).Times(0);

  forwarder.Start();

  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(IpSecPacketForwarderTest, TestTunnelWriteFail) {
  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Status write_status = absl::InternalError("Error writing to tunnel");

  std::vector<Packet> packets;
  packets.emplace_back("foo", 3, IPProtocol::kIPv6, []() {});

  absl::Notification failed;
  absl::Notification network_closed;
  absl::Notification utun_closed;

  // Simulate one successful read and then a blocking read.
  EXPECT_CALL(network_socket_, ReadPackets())
      .WillOnce(testing::Return(std::move(packets)))
      .WillOnce([&network_closed]() {
        network_closed.WaitForNotification();
        return std::vector<Packet>();
      });

  // Unblock the ReadPackets call.
  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  // Simulate a failed write.
  EXPECT_CALL(utun_interface_, WritePackets(testing::_))
      .WillOnce(testing::Return(write_status));

  // Simulate a blocking read until the socket is closed.
  EXPECT_CALL(utun_interface_, ReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  // Unblock the ReadPackets call.
  EXPECT_CALL(utun_interface_, CancelReadPackets()).WillOnce([&utun_closed]() {
    utun_closed.Notify();
    return absl::OkStatus();
  });

  EXPECT_CALL(notification_, IpSecPacketForwarderPermanentFailure(
                                 write_status, /*forwarder_id=*/123))
      .WillOnce([&failed]() { failed.Notify(); });

  forwarder.Start();

  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  notification_thread_.Stop();
  notification_thread_.Join();
}

TEST_F(IpSecPacketForwarderTest, TestTunnelReadFail) {
  auto forwarder = IpSecPacketForwarder(&utun_interface_, &network_socket_,
                                        &notification_thread_, &notification_,
                                        /*forwarder_id=*/123);

  absl::Status read_status = absl::InternalError("Error reading from tunnel");

  absl::Notification failed;
  absl::Notification network_closed;

  EXPECT_CALL(network_socket_, ReadPackets()).WillOnce([&network_closed]() {
    network_closed.WaitForNotification();
    return std::vector<Packet>();
  });

  EXPECT_CALL(network_socket_, CancelReadPackets())
      .WillOnce([&network_closed]() {
        network_closed.Notify();
        return absl::OkStatus();
      });

  EXPECT_CALL(utun_interface_, ReadPackets())
      .WillOnce(testing::Return(read_status));

  EXPECT_CALL(notification_,
              IpSecPacketForwarderFailed(read_status, /*forwarder_id=*/123))
      .WillOnce([&failed]() { failed.Notify(); });

  EXPECT_CALL(network_socket_, Close()).Times(0);

  forwarder.Start();

  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Milliseconds(100)));

  forwarder.Stop();

  notification_thread_.Stop();
  notification_thread_.Join();
}

}  // namespace
}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
