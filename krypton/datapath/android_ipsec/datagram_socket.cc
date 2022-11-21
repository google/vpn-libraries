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

#include <sys/socket.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

namespace {
constexpr int kMaxPacketSize = 4096;
}  // namespace

absl::StatusOr<std::unique_ptr<DatagramSocket>> DatagramSocket::Create(
    int socket_fd) {
  auto socket = std::unique_ptr<DatagramSocket>(new DatagramSocket(socket_fd));
  PPN_RETURN_IF_ERROR(socket->Init());
  return socket;
}

DatagramSocket::DatagramSocket(int socket_fd) : socket_fd_(socket_fd) {}

DatagramSocket::~DatagramSocket() {
  if (socket_fd_ >= 0) {
    PPN_LOG_IF_ERROR(Close());
  }

  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(close_event_.fd()));
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
  PPN_LOG_IF_ERROR(close_event_.Notify(1));
  return absl::OkStatus();
}

absl::StatusOr<std::vector<Packet>> DatagramSocket::ReadPackets() {
  if (socket_fd_ < 0) {
    return absl::InternalError("Attempted to read on a closed socket.");
  }
  EventsHelper::Event event;
  int num_events;
  auto status = events_helper_.Wait(&event, 1, -1, &num_events);
  int fd = socket_fd_;
  if (!status.ok()) {
    return absl::InternalError(absl::Substitute(
        "Failed to listen for events on socket $0: $1", fd, strerror(errno)));
  }

  int notified_fd = datapath::android::EventsHelper::FileFromEvent(event);
  if (notified_fd == close_event_.fd()) {
    // An empty vector without an error status should be interpreted as a close
    return std::vector<Packet>();
  }
  if (datapath::android::EventsHelper::FileHasError(event)) {
    return absl::InternalError(
        absl::Substitute("Read on socket $0 failed.", fd));
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

  // Should never get here
  return absl::InternalError("Unexpected event occurred.");
}

absl::Status DatagramSocket::WritePackets(std::vector<Packet> packets) {
  int fd = socket_fd_;
  if (fd < 0) {
    return absl::InternalError("Attempted to write to a closed socket.");
  }
  for (const auto& packet : packets) {
    int write_bytes;
    do {
      write_bytes = write(fd, packet.data().data(), packet.data().size());
    } while (write_bytes == -1 && errno == EINTR);
    if (write_bytes == -1 || write_bytes != packet.data().size()) {
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

  // Parse the endpoint into an ip_range so that we can use its utility to
  // convert the address into a sockaddr.
  PPN_ASSIGN_OR_RETURN(auto ip_range, utils::IPRange::Parse(dest.address()));

  int port = dest.port();
  LOG(INFO) << "Connecting FD=" << fd << " to " << dest.ToString();

  // Convert the address into a sockaddr so we can use it with connect().
  sockaddr_storage addr;
  socklen_t addr_size = 0;
  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(port, &addr, &addr_size));

  if (addr_size == 0) {
    return absl::InternalError("Got addr_size == 0.");
  }

  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), addr_size) != 0) {
    return absl::InternalError(
        absl::StrCat("Error connecting FD=", fd, ": ", strerror(errno)));
  }
  return absl::OkStatus();
}

std::string DatagramSocket::DebugString() {
  return absl::StrCat("FD=", socket_fd_.load());
}

absl::Status DatagramSocket::Init() {
  int fd = socket_fd_;

  auto status = events_helper_.AddFile(fd, EventsHelper::EventReadableFlags());
  if (status.ok()) {
    status = events_helper_.AddFile(close_event_.fd(),
                                    EventsHelper::EventReadableFlags());
    if (!status.ok()) {
      LOG(ERROR) << "Failed to add close event for socket " << fd
                 << " to EventsHelper: " << status;
    }
  } else {
    LOG(ERROR) << "Failed to add socket " << fd
               << " to EventsHelper: " << status;
  }

  if (!status.ok()) {
    PPN_LOG_IF_ERROR(Close());
    return status;
  }

  return absl::OkStatus();
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
