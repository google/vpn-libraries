// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/datapath/android_ipsec/datagram_socket.h"

#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

namespace {
constexpr int kMaxPacketSize = 4096;
}  // namespace

absl::StatusOr<std::unique_ptr<DatagramSocket>> DatagramSocket::Create(
    int socket_fd) {
  auto socket = absl::WrapUnique(new DatagramSocket(socket_fd));
  PPN_RETURN_IF_ERROR(socket->Init());
  return socket;
}

absl::StatusOr<std::unique_ptr<DatagramSocket>> DatagramSocket::Create(
    int socket_fd, std::unique_ptr<MtuTrackerInterface> mtu_tracker) {
  auto socket = absl::WrapUnique(new DatagramSocket(socket_fd));
  PPN_RETURN_IF_ERROR(socket->Init());
  PPN_RETURN_IF_ERROR(socket->EnablePathMtuDiscovery(std::move(mtu_tracker)));
  return socket;
}

DatagramSocket::DatagramSocket(int socket_fd)
    : socket_fd_(socket_fd),
      dynamic_mtu_enabled_(false),
      uplink_packets_dropped_(0),
      kernel_mtu_(INT_MAX),
      mtu_tracker_(nullptr) {}

DatagramSocket::~DatagramSocket() {
  if (socket_fd_ >= 0) {
    PPN_LOG_IF_ERROR(Close());
  }

  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(cancel_read_event_.fd()));
}

absl::Status DatagramSocket::Close() {
  int fd = socket_fd_.exchange(-1);
  if (fd < 0) {
    LOG(WARNING) << "Attempted to close socket that was already closed.";
    return absl::OkStatus();
  }
  LOG(INFO) << "Closing Socket FD=" << fd;
  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(fd));
  shutdown(fd, SHUT_RDWR);
  close(fd);
  PPN_LOG_IF_ERROR(CancelReadPackets());
  return absl::OkStatus();
}

absl::Status DatagramSocket::CancelReadPackets() {
  return cancel_read_event_.Notify(1);
}

absl::StatusOr<std::vector<Packet>> DatagramSocket::ReadPackets() {
  if (socket_fd_ < 0) {
    return absl::InternalError("Attempted to read on a closed socket.");
  }
  while (true) {
    EventsHelper::Event event;
    int num_events;
    auto status = events_helper_.Wait(&event, 1, -1, &num_events);
    int fd = socket_fd_;
    if (!status.ok()) {
      return absl::InternalError(absl::Substitute(
          "Failed to listen for events on socket $0: $1", fd, strerror(errno)));
    }

    int notified_fd = datapath::android::EventsHelper::FileFromEvent(event);
    if (notified_fd == cancel_read_event_.fd()) {
      PPN_RETURN_IF_ERROR(ClearEventFd(notified_fd));
      // Indicate clean exit with an empty vector
      return std::vector<Packet>();
    }
    if (datapath::android::EventsHelper::FileHasError(event)) {
      // Process the socket error queue.
      absl::MutexLock lock(&mutex_);
      PPN_RETURN_IF_ERROR(ProcessSocketErrorQueue());
      continue;
    }
    if (datapath::android::EventsHelper::FileCanRead(event)) {
      if (fd < 0) {
        return absl::InternalError("Attempted to read on a closed socket.");
      }
      // TODO: Do reads in batches.

      // TODO: Don't allocate new memory for every packet.
      char* buffer = new char[kMaxPacketSize];

      int read_bytes;
      do {
        read_bytes = read(fd, buffer, kMaxPacketSize);
      } while (read_bytes == -1 && errno == EINTR);

      if (read_bytes <= 0) {
        delete[] buffer;
        return absl::AbortedError(
            absl::Substitute("Reading from FD $0: $1", fd, strerror(errno)));
      }

      std::vector<Packet> packets;
      packets.emplace_back(buffer, read_bytes, IPProtocol::kUnknown,
                           [buffer]() { delete[] buffer; });

      return packets;
    }
  }
  // Should never get here
  return absl::InternalError("Unexpected event occurred.");
}

absl::Status DatagramSocket::WritePackets(std::vector<Packet> packets) {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError("Attempted to write to a closed socket.");
  }
  for (const auto& packet : packets) {
    // Check if the packet is too large to be sent
    if (dynamic_mtu_enabled_ &&
        packet.data().size() > mtu_tracker_->GetTunnelMtu()) {
      ++uplink_packets_dropped_;
      continue;
    }

    int write_bytes;
    do {
      write_bytes = write(fd, packet.data().data(), packet.data().size());
    } while (write_bytes == -1 && errno == EINTR);
    if (write_bytes == -1 || write_bytes != packet.data().size()) {
      // The message being too large indicates an MTU update has occurred.
      if (dynamic_mtu_enabled_ && errno == EMSGSIZE) {
        // Process the socket error queue to search for MTU updates and then
        // update the MTU tracker.
        absl::MutexLock lock(&mutex_);
        PPN_RETURN_IF_ERROR(ProcessSocketErrorQueue());
        mtu_tracker_->UpdateMtu(kernel_mtu_);
        ++uplink_packets_dropped_;
        continue;
      }
      return absl::InternalError(
          absl::StrCat("Error writing to FD=", fd, ": ", strerror(errno)));
    }
  }
  return absl::OkStatus();
}

absl::Status DatagramSocket::Connect(Endpoint dest) {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError("Attempted to write to a closed socket.");
  }

  LOG(INFO) << "Connecting FD=" << fd << " to " << dest.ToString();

  // Convert the address into a sockaddr so we can use it with connect().
  PPN_ASSIGN_OR_RETURN(auto sockaddr_info, dest.GetSockAddr());

  if (sockaddr_info.socklen == 0) {
    return absl::InternalError("Got addr_size == 0.");
  }

  if (connect(fd, reinterpret_cast<sockaddr*>(&sockaddr_info.sockaddr),
              sockaddr_info.socklen) != 0) {
    return absl::InternalError(
        absl::StrCat("Error connecting FD=", fd, ": ", strerror(errno)));
  }

  if (dynamic_mtu_enabled_) {
    PPN_RETURN_IF_ERROR(UpdateMtuFromKernel(dest.ip_protocol()));
  }

  return absl::OkStatus();
}

int DatagramSocket::GetFd() { return socket_fd_; }

void DatagramSocket::GetDebugInfo(DatapathDebugInfo* debug_info) {
  debug_info->set_uplink_packets_dropped(uplink_packets_dropped_);
}

std::string DatagramSocket::DebugString() {
  return absl::StrCat("FD=", socket_fd_.load());
}

absl::Status DatagramSocket::Init() {
  int fd = socket_fd_;

  auto status = events_helper_.AddFile(fd, EventsHelper::EventReadableFlags());
  if (!status.ok()) {
    LOG(ERROR) << "Failed to add fd " << fd << " to EventsHelper: " << status;
    PPN_LOG_IF_ERROR(Close());
    return status;
  }

  status = events_helper_.AddFile(cancel_read_event_.fd(),
                                  EventsHelper::EventReadableFlags());
  if (!status.ok()) {
    LOG(ERROR) << "Failed to add cancel read event with fd " << fd
               << " to EventsHelper: " << status;
    PPN_LOG_IF_ERROR(Close());
    return status;
  }

  return absl::OkStatus();
}

absl::Status DatagramSocket::ClearEventFd(int fd) {
  uint64_t tmp;
  if (read(fd, &tmp, sizeof(tmp)) == -1) {
    return absl::InternalError(
        absl::StrCat("Failed to clear EventFd ", fd, ": ", strerror(errno)));
  }
  return absl::OkStatus();
}

absl::Status DatagramSocket::EnablePathMtuDiscovery(
    std::unique_ptr<MtuTrackerInterface> mtu_tracker) {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError("Attempted to set options on a closed socket.");
  }

  LOG(INFO) << "Enabling Path MTU Discovery on socket " << fd;

  int af;
  socklen_t opt_len = sizeof(af);
  if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &af, &opt_len) == -1) {
    return absl::InternalError(absl::StrCat("Reading SO_DOMAIN failed on fd ",
                                            fd, ": ", strerror(errno)));
  }

  bool ipv4_possible = (af == AF_INET);

  if (af == AF_INET6) {
    // Enable IPv6 PMTUD
    int value = IPV6_PMTUDISC_DO;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value,
                   sizeof(value)) != 0) {
      return absl::InternalError(
          absl::StrCat("Setting IPV6_MTU_DISCOVER failed on fd ", fd, ": ",
                       strerror(errno)));
    }

    // Enable error queue to allow processing of EMSGSIZE errors even if socket
    // is unconnected.
    value = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &value, sizeof(value)) !=
        0) {
      return absl::InternalError(absl::StrCat(
          "Setting IPV6_RECVERR failed on fd ", fd, ": ", strerror(errno)));
    }

    // Check if socket supports IPv4
    int v6_only;
    socklen_t opt_len = sizeof(v6_only);
    getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, &opt_len);

    ipv4_possible = (v6_only == 0);
  }

  // Enable IPv4 PMTUD if the socket supports IPv4
  if (ipv4_possible) {
    int value = IP_PMTUDISC_DO;
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value)) !=
        0) {
      return absl::InternalError(absl::StrCat(
          "Setting IP_MTU_DISCOVER failed on fd ", fd, ": ", strerror(errno)));
    }

    // Enable error queue to allow processing of EMSGSIZE errors even if socket
    // is unconnected.
    value = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &value, sizeof(value)) != 0) {
      return absl::InternalError(absl::StrCat(
          "Setting IP_RECVERR failed on fd ", fd, ": ", strerror(errno)));
    }
  }

  if (mtu_tracker == nullptr) {
    return absl::InternalError(
        "Enabled Path MTU Discovery with a null MTU Tracker");
  }
  mtu_tracker_ = std::move(mtu_tracker);

  dynamic_mtu_enabled_ = true;

  return absl::OkStatus();
}

absl::Status DatagramSocket::UpdateMtuFromKernel(IPProtocol ip_protocol) {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError(
        "Attempted to get kernel MTU on a closed socket.");
  }

  absl::MutexLock lock(&mutex_);
  bool dest_ipv6 = ip_protocol == IPProtocol::kIPv6;
  socklen_t mtu_len = sizeof(kernel_mtu_);
  int ret = getsockopt(fd, dest_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                       dest_ipv6 ? IPV6_MTU : IP_MTU, &kernel_mtu_, &mtu_len);
  if (ret != 0) {
    return absl::InternalError(absl::StrCat(
        "Failed to read the kernel MTU on fd ", fd, ": ", strerror(errno)));
  }

  mtu_tracker_->UpdateMtu(kernel_mtu_);
  return absl::OkStatus();
}

absl::Status DatagramSocket::ProcessSocketErrorQueue() {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError("Attempted to read error on a closed socket.");
  }

  // Set up to receive control messages from error queue
  char cmsg_buffer[1024];
  memset(cmsg_buffer, 0, sizeof(cmsg_buffer));
  msghdr msg{};
  msg.msg_control = cmsg_buffer;
  msg.msg_controllen = sizeof(cmsg_buffer);
  if (recvmsg(fd, &msg, MSG_ERRQUEUE) == -1) {
    // Return OK if there was just nothing in the queue.
    if (errno == EWOULDBLOCK) {
      return absl::OkStatus();
    }
    return absl::InternalError("Failed to read socket error.");
  }

  // Process all control messages and look for EMSGSIZE error with MTU update
  for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_len > 0 &&
        ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVERR) ||
         (cmsg->cmsg_level == IPPROTO_IPV6 &&
          cmsg->cmsg_type == IPV6_RECVERR))) {
      sock_extended_err* err =
          reinterpret_cast<sock_extended_err*>(CMSG_DATA(cmsg));
      // The EMSGSIZE error indicates a potential path MTU update.
      if (err->ee_errno == EMSGSIZE) {
        if (err->ee_info < kernel_mtu_) {
          kernel_mtu_ = err->ee_info;
        }
        continue;
      }
      // The EINTR error is expected from reads and writes.
      if (err->ee_errno == EINTR) continue;

      // Any other socket errors should be considered a failure.
      return absl::InternalError(absl::StrCat("Unexpected error on fd ", fd,
                                              ": ", strerror(err->ee_errno)));
    }
  }

  return absl::OkStatus();
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
