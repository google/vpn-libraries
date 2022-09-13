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

#include "privacy/net/krypton/fd_packet_pipe.h"

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/log/die_if_null.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace {
constexpr int kMaxPacketSize = 4096;
constexpr int kMaxEvents = 4;

}  // namespace

FdPacketPipe::~FdPacketPipe() {
  absl::MutexLock lock(&mutex_);
  if (fd_ >= 0) {
    LOG(FATAL) << "Tried to destroy unclosed packet pipe " << DebugString();
  }
}

void FdPacketPipe::Run() {
  auto status = RunInternal();
  if (!status.ok()) {
    handler_(status, std::vector<Packet>());
  }
  // Signal any callers of StopReadingPackets that reading has fully stopped.
  {
    absl::MutexLock lock(&mutex_);
    reading_ = false;
    reading_stopped_.Signal();
  }
}

void FdPacketPipe::Close() {
  StopReadingPackets().IgnoreError();
  {
    absl::MutexLock lock(&mutex_);
    close(fd_);
    fd_ = -1;
  }
}

absl::Status FdPacketPipe::StopReadingPackets() {
  absl::MutexLock lock(&mutex_);
  if (!reading_) {
    // Just consider this a warning, since it may be easier for the datapath to
    // just always call this, without checking whether the pipe is actually
    // running.
    LOG(WARNING) << "StopReadingPackets called on pipe that's already stopped: "
                 << DebugString();
    return absl::OkStatus();
  }
  // Signal the Run thread to stop.
  PPN_RETURN_IF_ERROR(shutdown_event_->Notify(1));
  // Wait for it to actually be finished. Otherwise, this pipe might send a
  // packet after this method returns.
  reading_stopped_.Wait(&mutex_);
  return absl::OkStatus();
}

absl::Status FdPacketPipe::SetupReading() {
  absl::MutexLock lock(&mutex_);
  if (fd_ < 0) {
    return absl::FailedPreconditionError(
        "Tried to ReadPackets from closed FdPacketPipe");
  }
  if (reading_) {
    return absl::FailedPreconditionError(absl::StrCat(
        "ReadPackets called on already running pipe ", DebugString()));
  }
  reading_ = true;
  shutdown_event_ = std::make_unique<datapath::android::EventFd>();
  return absl::OkStatus();
}

void FdPacketPipe::ReadPackets(
    std::function<bool(absl::Status, std::vector<Packet>)> handler) {
  auto status = SetupReading();
  if (!status.ok()) {
    handler(status, std::vector<Packet>());
    return;
  }
  handler_ = std::move(ABSL_DIE_IF_NULL(handler));
  thread_.Post([this] { Run(); });
}

absl::Status FdPacketPipe::WritePackets(std::vector<Packet> packets) {
  if (fd_ == -1) {
    return absl::InternalError("pipe is closed");
  }

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

void FdPacketPipe::PostDatapathFailure(const absl::Status& status) {
  bool expected = false;
  if (!permanent_failure_notification_raised_.compare_exchange_strong(expected,
                                                                      true)) {
    LOG(ERROR) << "Datapath permanent failure [Dedup]:" << status;
    return;
  }

  LOG(ERROR) << "FdPacketPipe permanent failure: " << status;
  Packet packet;
  handler_(absl::InternalError("Permanent failure"), std::vector<Packet>());
}

absl::Status FdPacketPipe::RunInternal() {
  LOG(INFO) << "Starting packet processing " << DebugString();
  auto make_cleanup = absl::MakeCleanup(
      [this]() { LOG(INFO) << "Exiting packet processing " << DebugString(); });

  int shutdown_event_fd;
  {
    absl::MutexLock lock(&mutex_);
    shutdown_event_fd = shutdown_event_->fd();
  }

  // Build the event fd with fd_ & shutdown.
  PPN_RETURN_IF_ERROR(datapath::android::SetSocketBlocking(fd_));
  // Once the FD is added to the events, it should not be closed without
  // removing it from here. epoll will not provide feedback when the fd is
  // closed by another thread.
  PPN_RETURN_IF_ERROR(events_helper_.AddFile(
      fd_, datapath::android::EventsHelper::EventReadableFlags()));
  auto events_helper_cleanup = absl::MakeCleanup(
      [this]() { PPN_LOG_IF_ERROR(events_helper_.RemoveFile(fd_)); });
  PPN_RETURN_IF_ERROR(events_helper_.AddFile(
      shutdown_event_fd,
      datapath::android::EventsHelper::EventReadableFlags()));
  auto shutdown_event_cleanup = absl::MakeCleanup([this, shutdown_event_fd]() {
    PPN_LOG_IF_ERROR(events_helper_.RemoveFile(shutdown_event_fd));
  });

  started_listening_ = true;

  datapath::android::EventsHelper::Event events[kMaxEvents];
  while (true) {
    int num_events = 0;
    auto status = events_helper_.Wait(events, kMaxEvents, -1, &num_events);
    if (!status.ok()) {
      LOG(ERROR) << "Reading failed: " << DebugString();
      PostDatapathFailure(status);
      continue;
    }

    for (int i = 0; i < num_events; ++i) {
      int notified_fd =
          datapath::android::EventsHelper::FileFromEvent(events[i]);
      if (notified_fd == shutdown_event_fd) {
        LOG(INFO) << "Shutting down PacketPipe " << DebugString();
        return absl::OkStatus();
      }
      if (datapath::android::EventsHelper::FileHasError(events[i])) {
        LOG(INFO) << "Data loss error " << DebugString();
        PostDatapathFailure(absl::DataLossError("Data loss"));
        continue;
        // continue reading from socket in case there might be data.
      }
      if (datapath::android::EventsHelper::FileCanRead(events[i])) {
        char* buffer = new char[kMaxPacketSize];

        int read_bytes;
        do {
          read_bytes = read(notified_fd, buffer, kMaxPacketSize);
        } while (read_bytes == -1 && errno == EINTR);

        if (read_bytes <= 0) {
          PostDatapathFailure(absl::DataLossError(absl::Substitute(
              "Reading from FD $0: $1", fd_, strerror(errno))));
          continue;
        }

        Packet packet(buffer, read_bytes, IPProtocol::kUnknown,
                      [&buffer]() { delete[] buffer; });
        std::vector<Packet> packets;
        packets.emplace_back(std::move(packet));
        if (!handler_(absl::OkStatus(), std::move(packets))) {
          return absl::OkStatus();
        }
      }
    }
  }
  return absl::OkStatus();
}

absl::Status FdPacketPipe::Connect(const Endpoint& endpoint) {
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

}  // namespace krypton
}  // namespace privacy
