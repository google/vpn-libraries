// Copyright 2023 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TEST_UTILS_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TEST_UTILS_H_

#include <cstdint>

#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/synchronization/notification.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

enum class SocketMode { kBlocking, kNonBlocking };

// A local TCP socket, whose IP version, local address to bind, blocking mode,
// and timeout can be configured via the corresponding constructors.
//
// Example:
//   LocalTcpSocket sock(IpVersion::kIpv6, /* timeout_ms = */ 100,
//                       SocketMode::kBlocking);
//   LocalTcpSocket sock(StringToSocketAddressOrDie("127.0.0.1:999"),
//                       /* timeout_ms = */ 100, SocketMode::kNonBlocking);
class LocalTcpSocket {
 public:
  // Bind to local loopback address.
  LocalTcpSocket(IPProtocol ip_version, unsigned int timeout_ms,
                 SocketMode mode);
  ~LocalTcpSocket();

  int fd() const { return fd_; }

  // Once called, user should close the returned fd.
  int DetachFd() {
    detached_ = true;
    return fd();
  }

  const Endpoint& endpoint() const { return endpoint_; }

 private:
  LocalTcpSocket(IPProtocol ip_version, unsigned int timeout_ms);

  bool detached_ = false;
  int fd_;
  Endpoint endpoint_;
};

// A local TCP server that simulates the functionality of MSS detection of the
// dataplane server. This server will accept a single connection, optionally
// send 4-byte data to the client, and then shut down.
// Not copyable or movable.
class LocalTcpMssMtuServer {
 public:
  // sock: pointer to the socket that is to be used by this server.
  // data: 4-byte data to be sent from the server.
  // send_data: If true, this server will send data_ over sock_ after accepting
  //            a connection. If false, this server will shut down after
  //            accepting the connection without sending the data.
  // server_up: to be notified after this server is ready to accept connections.
  LocalTcpMssMtuServer(LocalTcpSocket* sock, uint32_t data, bool send_data,
                       absl::Notification* server_up);

  // sock: pointer to the socket that is to be used by this server.
  // data: 4-byte data to be sent from the server.
  // send_data: If true, this server will send data_ over sock_ after accepting
  //            a connection. If false, this server will shut down after
  //            accepting the connection without sending the data.
  // server_up: to be notified after this server is ready to accept connections.
  // start_send_data: to be notified when this server should allow data to be
  //                  sent to the client.
  LocalTcpMssMtuServer(LocalTcpSocket* sock, uint32_t data, bool send_data,
                       absl::Notification* server_up,
                       absl::Notification* start_send_data);

  ~LocalTcpMssMtuServer() {
    server_thread_.Stop();
    server_thread_.Join();
  }

  // Not copyable or movable
  LocalTcpMssMtuServer(const LocalTcpMssMtuServer&) = delete;
  LocalTcpMssMtuServer& operator=(const LocalTcpMssMtuServer&) = delete;

 private:
  void Serve();

  // TCP socket associated with this server.
  LocalTcpSocket* sock_;
  // The data to be sent by this server.
  uint32_t data_;
  // If true, this server will send data_ over sock_ after accepting a
  // connection. If false, this server will shut down after accepting the
  // connection without sending the data.
  bool send_data_;
  // To be notified after this server is ready to accept connections.
  absl::Notification* server_up_;
  // To be notified when this server should allow data to be sent to the client.
  absl::Notification* start_send_data_;
  utils::LooperThread server_thread_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_TEST_UTILS_H_
