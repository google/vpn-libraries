/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SIMPLE_UDP_SERVER_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SIMPLE_UDP_SERVER_H_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/utils/utils.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace testing {

// Simple UDP server used for testing.
class SimpleUdpServer {
 public:
  SimpleUdpServer() {
    // Creating socket file descriptor
    // Forge can only create v6 sockets.
    if ((fd_ = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
      LOG(FATAL) << "Error creating datagram socket";
    }
    struct sockaddr_in6 servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = 0;
    // Bind the socket with the server address
    if (bind(fd_, reinterpret_cast<const struct sockaddr *>(&servaddr),
             sizeof(servaddr)) < 0) {
      LOG(FATAL) << "Failed to bind on the socket";
    }

    // Get the port that was bound.
    memset(&servaddr, 0, sizeof(servaddr));
    socklen_t addr_len = sizeof(servaddr);
    if (getsockname(fd_, reinterpret_cast<sockaddr *>(&servaddr), &addr_len) !=
        0) {
      LOG(FATAL) << "getsockname: " << strerror(errno);
    }
    port_ = ntohs(servaddr.sin6_port);
    LOG(INFO) << "Bound to port " << port_;
  }
  ~SimpleUdpServer() {
#ifdef _WIN32
    closesocket(fd_);
#else
    close(fd_);
#endif
  }

  // Sends a packet from the server to the given port.
  void SendSamplePacket(int remote_port, absl::string_view message) {
    struct sockaddr_in6 servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    // Filling server information
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(remote_port);
    sendto(fd_, message.data(), message.size(), 0,
           reinterpret_cast<sockaddr *>(&servaddr), sizeof(servaddr));
  }

  absl::Status Connect(int remote_port) {
    struct sockaddr_in6 servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    // Filling server information
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(remote_port);
    auto connect_status =
        connect(fd_, reinterpret_cast<sockaddr *>(&servaddr), sizeof(servaddr));
    if (connect_status < 0) {
      return absl::FailedPreconditionError(
          "Failed to connect to remote address");
    }
    return absl::OkStatus();
  }

  // Receives a single packet and returns port and data.
  absl::StatusOr<std::pair<int, std::string>> ReceivePacket() {
    sockaddr_in6 client_socket;
    socklen_t client_socket_len = sizeof(client_socket);
    char buffer[4096];
    int ret = recvfrom(fd_, buffer, sizeof(buffer), 0,
                       reinterpret_cast<sockaddr *>(&client_socket),
                       &client_socket_len);
    if (ret < 0) {
      return absl::InternalError("unable to recvfrom");
    }

    std::string data(buffer, ret);
    int port = ntohs(client_socket.sin6_port);

    LOG(INFO) << "Received packet: " << utils::StringToHexASCIIDump(data);
    LOG(INFO) << "Client port: " << port;
    return std::make_pair(port, data);
  }

  int fd() { return fd_; }
  int port() { return port_; }

 private:
  int fd_ = -1;
  int port_;
};
}  // namespace testing
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_SIMPLE_UDP_SERVER_H_
