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
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/base/call_once.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

namespace {
constexpr int kMaxPacketSize = 4096;
}  // namespace

DatagramSocket::DatagramSocket(int fd) : fd_(fd) {
  auto status = CreateCloseEvent();
  if (!status.ok()) {
    // There really is no way to recover from not being able to create an event.
    LOG(FATAL) << "unable to listen on fd=" << fd_ << ": " << status;
  }
}

absl::Status DatagramSocket::CreateCloseEvent() {
  // Build the event fd with fd_ & shutdown.
  PPN_RETURN_IF_ERROR(datapath::android::SetSocketBlocking(fd_));
  // Once the FD is added to the events, it should not be closed without
  // removing it from here. epoll will not provide feedback when the fd is
  // closed by another thread.
  PPN_RETURN_IF_ERROR(events_helper_.AddFile(
      fd_, datapath::android::EventsHelper::EventReadableFlags()));
  PPN_RETURN_IF_ERROR(events_helper_.AddFile(
      shutdown_event_.fd(),
      datapath::android::EventsHelper::EventReadableFlags()));

  return absl::OkStatus();
}

DatagramSocket::~DatagramSocket() {
  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(shutdown_event_.fd()));
}

absl::Status DatagramSocket::Close() {
  PPN_RETURN_IF_ERROR(shutdown_event_.Notify(1));
  // Remove the FD from the event before closing it.
  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(fd_));
  close(fd_);
  return absl::OkStatus();
}

absl::Status DatagramSocket::WritePackets(std::vector<Packet> packets) {
  for (const auto& packet : packets) {
    int write_bytes;
    do {
      write_bytes = write(fd_, packet.data().data(), packet.data().size());
    } while (write_bytes == -1 && errno == EINTR);
    if (write_bytes == -1) {
      return absl::InternalError(
          absl::StrCat("Error writing to FD=", fd_, ": ", strerror(errno)));
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::vector<Packet>> DatagramSocket::ReadPackets() {
  datapath::android::EventsHelper::Event event;
  int num_events = 0;
  auto status = events_helper_.Wait(&event, /*max_events=*/1, -1, &num_events);
  if (!status.ok()) {
    LOG(ERROR) << "Reading failed: " << DebugString() << ": " << status;
    return status;
  }

  // This shouldn't happen, but ignore it if it does.
  if (num_events == 0) {
    return std::vector<Packet>();
  }

  // TODO: Do reads in batches.

  int notified_fd = datapath::android::EventsHelper::FileFromEvent(event);
  if (notified_fd == shutdown_event_.fd()) {
    LOG(INFO) << "Aborting closed read on " << DebugString();
    return absl::AbortedError("file descriptor is closed");
  }
  if (datapath::android::EventsHelper::FileHasError(event)) {
    LOG(INFO) << "Data loss error " << DebugString();
    return absl::DataLossError("data loss");
  }
  if (datapath::android::EventsHelper::FileCanRead(event)) {
    // TODO: Don't allocate new memory for every packet.
    char* buffer = new char[kMaxPacketSize];

    int read_bytes;
    do {
      read_bytes = read(notified_fd, buffer, kMaxPacketSize);
    } while (read_bytes == -1 && errno == EINTR);

    if (read_bytes <= 0) {
      delete[] buffer;
      return absl::DataLossError(
          absl::Substitute("Reading from FD $0: $1", fd_, strerror(errno)));
    }

    Packet packet(buffer, read_bytes, IPProtocol::kUnknown,
                  [buffer]() { delete[] buffer; });
    std::vector<Packet> packets;
    packets.emplace_back(std::move(packet));

    return packets;
  }

  // This should never happen.
  return absl::InternalError("unknown event type");
}

absl::Status DatagramSocket::Connect(const Endpoint& endpoint) {
  // Parse the endpoint into an ip_range so that we can use its utility to
  // convert the address into a sockaddr.
  PPN_ASSIGN_OR_RETURN(auto ip_range,
                       utils::IPRange::Parse(endpoint.address()));

  int port = endpoint.port();
  LOG(INFO) << "Connecting FD=" << fd_ << " to " << endpoint.ToString();

  // Convert the address into a sockaddr so we can use it with connect().
  sockaddr_storage addr;
  socklen_t addr_size = 0;
  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(port, &addr, &addr_size));

  if (addr_size == 0) {
    return absl::InternalError("Got addr_size == 0.");
  }

  if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), addr_size) != 0) {
    return absl::InternalError(
        absl::StrCat("Error connecting FD=", fd_, ": ", strerror(errno)));
  }
  return absl::OkStatus();
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
