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

#include "privacy/net/krypton/datapath/android_ipsec/test_utils.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

void CloseOrDie(int fd) {
  CHECK(close(fd) == 0) << "close: " << fd << " " << strerror(errno);
}

void SetTimeout(int fd, unsigned int timeout_ms) {
  timeval timeout = absl::ToTimeval(absl::Milliseconds(timeout_ms));
  CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0)
      << "SO_RCVTIMEO: " << strerror(errno);
  CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0)
      << "SO_SNDTIMEO: " << strerror(errno);
}

}  // namespace

LocalTcpSocket::LocalTcpSocket(IPProtocol ip_version, unsigned int timeout_ms)
    : endpoint_("", "", 0, IPProtocol::kUnknown) {
  fd_ = socket(ip_version == IPProtocol::kIPv6 ? AF_INET6 : AF_INET,
               SOCK_STREAM, 0);
  PCHECK(fd_ != -1) << "Unable to create socket";

  sockaddr_storage addr{};
  std::string ip;
  if (ip_version == IPProtocol::kIPv6) {
    sockaddr_in6* ipv6_addr = reinterpret_cast<sockaddr_in6*>(&addr);
    ipv6_addr->sin6_family = AF_INET6;
    ipv6_addr->sin6_port = 0;
    inet_pton(AF_INET6, "::1", &ipv6_addr->sin6_addr);
    ip = "::1";
  } else {
    sockaddr_in* ipv4_addr = reinterpret_cast<sockaddr_in*>(&addr);
    ipv4_addr->sin_family = AF_INET;
    ipv4_addr->sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &ipv4_addr->sin_addr);
    ip = "127.0.0.1";
  }
  PCHECK(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
      << "bind failed";

  socklen_t size = sizeof(addr);
  PCHECK(getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &size) == 0)
      << "getsockname failed";

  int port;
  std::string host_port;
  if (ip_version == IPProtocol::kIPv6) {
    sockaddr_in6* ipv6_addr = reinterpret_cast<sockaddr_in6*>(&addr);
    port = ntohs(ipv6_addr->sin6_port);
    host_port = absl::StrCat("[", ip, "]:", port);
  } else {
    sockaddr_in* ipv4_addr = reinterpret_cast<sockaddr_in*>(&addr);
    port = ntohs(ipv4_addr->sin_port);
    host_port = absl::StrCat(ip, ":", port);
  }

  endpoint_ = Endpoint(host_port, ip, port, ip_version);

  SetTimeout(fd_, timeout_ms);
}

LocalTcpSocket::LocalTcpSocket(IPProtocol ip_version, unsigned int timeout_ms,
                               SocketMode mode)
    : LocalTcpSocket(ip_version, timeout_ms) {
  if (mode == SocketMode::kBlocking) {
    CHECK_OK(SetSocketBlocking(fd_));
  } else {
    CHECK_OK(SetSocketNonBlocking(fd_));
  }
}

LocalTcpSocket::LocalTcpSocket(const Endpoint& endpoint,
                               unsigned int timeout_ms, SocketMode mode)
    : endpoint_("", "", 0, IPProtocol::kUnknown) {
  bool is_ipv6 = endpoint.ip_protocol() == IPProtocol::kIPv6;
  fd_ = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
  PCHECK(fd_ != -1) << "Unable to create socket";

  sockaddr_storage addr{};
  if (endpoint.ip_protocol() == IPProtocol::kIPv6) {
    sockaddr_in6* ipv6_addr = reinterpret_cast<sockaddr_in6*>(&addr);
    ipv6_addr->sin6_family = AF_INET6;
    ipv6_addr->sin6_port = htons(endpoint.port());
    inet_pton(AF_INET6, endpoint.address().c_str(), &ipv6_addr->sin6_addr);
  } else {
    sockaddr_in* ipv4_addr = reinterpret_cast<sockaddr_in*>(&addr);
    ipv4_addr->sin_family = AF_INET;
    ipv4_addr->sin_port = htons(endpoint.port());
    inet_pton(AF_INET, endpoint.address().c_str(), &ipv4_addr->sin_addr);
  }

  PCHECK(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
      << "bind failed";
  endpoint_ = endpoint;
  SetTimeout(fd_, timeout_ms);

  if (mode == SocketMode::kBlocking) {
    CHECK_OK(SetSocketBlocking(fd_));
  } else {
    CHECK_OK(SetSocketNonBlocking(fd_));
  }
}

LocalTcpSocket::~LocalTcpSocket() {
  if (!detached_) {
    CloseOrDie(fd_);
  }
}

LocalTcpMssMtuServer::LocalTcpMssMtuServer(LocalTcpSocket* sock, uint32_t data,
                                           bool send_data,
                                           absl::Notification* server_up)
    : sock_(sock),
      data_(data),
      send_data_(send_data),
      server_up_(server_up),
      server_thread_("LocalTcpMssMtuServer") {
  server_thread_.Post([this] { Serve(); });
}

void LocalTcpMssMtuServer::Serve() {
  LOG(INFO) << "server thread started.";
  int sockfd = sock_->fd();

  int ret = listen(sockfd, 1);
  PCHECK(ret == 0) << "listen failed";
  server_up_->Notify();

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  int new_sock = accept(sockfd, reinterpret_cast<sockaddr*>(&addr), &addr_len);
  PCHECK(new_sock > 0) << "accept failed";
  absl::Cleanup new_sock_cleanup = [new_sock]() { close(new_sock); };

  LOG(INFO) << "server accepted a connection.";

  if (!send_data_) {
    LOG(INFO) << "server thread stopped without sending data to the client.";
    return;
  }

  uint32_t data = htonl(data_);
  ret = send(new_sock, reinterpret_cast<const void*>(&data), sizeof(data), 0);
  PCHECK(ret == sizeof(data)) << "send failed";

  char buf;
  // Wait for the client to close the connection.
  ret = recv(new_sock, &buf, 1, 0);
  PCHECK(ret == 0) << "recv failed";

  LOG(INFO) << "server thread stopped.";
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
