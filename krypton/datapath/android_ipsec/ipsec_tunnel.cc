// Copyright 2022 Google LLC
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

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_tunnel.h"

#include <sys/poll.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/fd_util.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

namespace {
constexpr int kMaxPacketSize = 4096;

constexpr int kWaitForever = -1;
constexpr absl::Duration kTunnelFlushDelay = absl::Minutes(1);
}  // namespace

absl::StatusOr<std::unique_ptr<IpSecTunnel>> IpSecTunnel::Create(
    int tunnel_fd, TimerManager* timer_manager) {
  auto tunnel = std::unique_ptr<IpSecTunnel>(new IpSecTunnel(timer_manager));
  PPN_RETURN_IF_ERROR(tunnel->Init());
  PPN_RETURN_IF_ERROR(tunnel->AdoptFd(tunnel_fd));
  return tunnel;
}

IpSecTunnel::IpSecTunnel(TimerManager* timer_manager)
    : flush_counter_(0),
      keepalive_timeout_ms_(kWaitForever),
      timer_manager_(timer_manager) {
  LOG(INFO) << "Creating tunnel " << GetDebugString();
}

IpSecTunnel::~IpSecTunnel() {
  LOG(INFO) << "Destroying tunnel " << GetDebugString();
  Close();
  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(cancel_read_event_.fd()));
}

absl::Status IpSecTunnel::AdoptFd(int fd) {
  absl::MutexLock lock(&mutex_);
  LOG(INFO) << "Tunnel adopting fd: " << fd;
  if (fd < 0) {
    return absl::InvalidArgumentError(absl::StrCat("Invalid fd: ", fd));
  }
  owned_fds_.push_back(fd);
  primary_fd_ = fd;
  // If there is already an fd that needs to be flushed start the FlushFdTimer.
  if (owned_fds_.size() > 1) {
    StartFlushFdTimer();
  }
  return events_helper_.AddFile(fd, EventsHelper::EventReadableFlags());
}

void IpSecTunnel::Close() {
  absl::MutexLock lock(&mutex_);
  LOG(INFO) << "Closing tunnel " << GetDebugString();
  CancelFlushFdTimerIfRunning();
  for (int owned_fd : owned_fds_) {
    CloseTunnelFd(owned_fd);
  }
  owned_fds_.clear();
  primary_fd_ = std::nullopt;
  CancelReadPackets();
}

absl::Status IpSecTunnel::Reset() {
  LOG(INFO) << "Reset called on tunnel " << GetDebugString();
  return ClearEventFd(cancel_read_event_);
}

void IpSecTunnel::CancelReadPackets() {
  LOG(INFO) << "CancelReadPackets called on tunnel " << GetDebugString();
  PPN_LOG_IF_ERROR(cancel_read_event_.Notify(1));
}

absl::StatusOr<std::vector<Packet>> IpSecTunnel::ReadPackets() {
  if (!primary_fd_.load()) {
    return absl::InternalError("Attempted to read without an fd.");
  }
  EventsHelper::Event event;
  int num_events;
  auto status =
      events_helper_.Wait(&event, 1, keepalive_timeout_ms_, &num_events);
  if (!status.ok()) {
    char buf[256];
    strerror_r(errno, buf, sizeof(buf));
    return absl::InternalError(
        absl::StrCat("Failed to listen for events on tunnel: ", buf));
  }

  // Send a keepalive packet if we time out
  if (num_events == 0) {
    static const char* buffer = "\xFF";
    std::vector<Packet> packets;
    packets.emplace_back(buffer, 1, IPProtocol::kUnknown, []() {});

    return packets;
  }
  int fd = datapath::android::EventsHelper::FileFromEvent(event);
  if (fd == cancel_read_event_.fd()) {
    // An empty vector without an error status should be interpreted as a
    // close
    LOG(INFO) << "Cancel read event received on tunnel " << GetDebugString();
    PPN_LOG_IF_ERROR(ClearEventFd(cancel_read_event_));
    return std::vector<Packet>();
  }
  if (datapath::android::EventsHelper::FileHasError(event)) {
    return absl::InternalError(absl::Substitute("Read on fd $0 failed.", fd));
  }
  if (datapath::android::EventsHelper::FileCanRead(event)) {
    // TODO: Do reads in batches.

    // TODO: Don't allocate new memory for every packet.
    char* buffer = new char[kMaxPacketSize];

    int read_bytes;
    do {
      read_bytes = read(fd, buffer, kMaxPacketSize);
    } while (read_bytes == -1 && errno == EINTR);

    if (read_bytes <= 0) {
      delete[] buffer;
      char buf[256];
      strerror_r(errno, buf, sizeof(buf));
      return absl::AbortedError(
          absl::Substitute("Reading from fd $0: $1", fd, buf));
    }

    std::vector<Packet> packets;
    packets.emplace_back(buffer, read_bytes, IPProtocol::kUnknown,
                         [buffer]() { delete[] buffer; });

    return packets;
  }

  // Should never get here
  return absl::InternalError("Unexpected event occurred.");
}

absl::Status IpSecTunnel::WritePackets(std::vector<Packet> packets) {
  std::optional<int> write_fd = primary_fd_;
  if (!write_fd) {
    return absl::InternalError("Attempted to write without an fd.");
  }
  for (const auto& packet : packets) {
    int write_bytes;
    do {
      write_bytes =
          write(*write_fd, packet.data().data(), packet.data().size());
    } while (write_bytes == -1 && errno == EINTR);
    if (write_bytes != packet.data().size()) {
      char buf[256];
      strerror_r(errno, buf, sizeof(buf));
      return absl::InternalError(
          absl::StrCat("Error writing to fd=", *write_fd, ": ", buf));
    }
  }
  return absl::OkStatus();
}

void IpSecTunnel::SetKeepaliveInterval(absl::Duration keepalive_interval) {
  keepalive_timeout_ms_ = absl::ToInt64Milliseconds(keepalive_interval);
  if (keepalive_timeout_ms_ <= 0) {
    keepalive_timeout_ms_ = kWaitForever;
  }
}

absl::Duration IpSecTunnel::GetKeepaliveInterval() {
  return (keepalive_timeout_ms_ == kWaitForever)
             ? absl::ZeroDuration()
             : absl::Milliseconds(keepalive_timeout_ms_);
}

bool IpSecTunnel::IsKeepaliveEnabled() {
  return (keepalive_timeout_ms_ != kWaitForever);
}

absl::Status IpSecTunnel::Init() {
  return events_helper_.AddFile(cancel_read_event_.fd(),
                                EventsHelper::EventReadableFlags());
}

bool IpSecTunnel::TunnelFdHasData(int fd) {
  pollfd event_pollfd;
  event_pollfd.fd = fd;
  event_pollfd.events = POLLIN;
  int ret = poll(&event_pollfd, /*nfds=*/1, /*timeout=*/0);
  if (ret <= 0) {
    // If there is no data left on this fd, or there was an error in the
    // poll, we will close it.
    if (ret < 0) {
      char buf[256];
      strerror_r(errno, buf, sizeof(buf));
      LOG(ERROR) << "Failed to poll fd " << fd << ": " << buf;
    } else {
      LOG(INFO) << "The tunnel fd " << fd << " has been flushed.";
    }
    return false;
  }
  return true;
}

void IpSecTunnel::CloseTunnelFd(int fd) {
  LOG(INFO) << "CloseFd called on tunnel " << GetDebugString() << " for fd "
            << fd;
  PPN_LOG_IF_ERROR(events_helper_.RemoveFile(fd));
  PPN_LOG_IF_ERROR(CloseFd(fd));
}

void IpSecTunnel::CloseNonPrimaryTunnelFds(bool skip_fds_with_data) {
  std::optional<int> primary_fd = primary_fd_;
  auto owned_fd_it = owned_fds_.begin();
  while (owned_fd_it != owned_fds_.end()) {
    if ((primary_fd && *owned_fd_it == *primary_fd) ||
        (skip_fds_with_data && TunnelFdHasData(*owned_fd_it))) {
      ++owned_fd_it;
      continue;
    }
    CloseTunnelFd(*owned_fd_it);
    owned_fd_it = owned_fds_.erase(owned_fd_it);
  }
}

absl::Status IpSecTunnel::ClearEventFd(const EventFd& event_fd) {
  int fd = event_fd.fd();
  LOG(INFO) << "ClearEventFd called on tunnel " << GetDebugString()
            << " for EventFd " << fd;
  pollfd event_pollfd;
  event_pollfd.fd = fd;
  event_pollfd.events = POLLIN;

  // Go through and read all events currently there to clear them.
  int ret = poll(&event_pollfd, /*nfds=*/1, /*timeout=*/0);
  while (ret > 0) {
    uint64_t tmp;
    if (read(fd, &tmp, sizeof(tmp)) == -1) {
      char buf[256];
      strerror_r(errno, buf, sizeof(buf));
      return absl::InternalError(
          absl::StrCat("Failed to read from EventFd ", fd, ": ", buf));
    }
    ret = poll(&event_pollfd, /*nfds=*/1, /*timeout=*/0);
  }

  if (ret < 0) {
    char buf[256];
    strerror_r(errno, buf, sizeof(buf));
    return absl::InternalError(
        absl::StrCat("Failed to poll EventFd ", fd, ": ", buf));
  }
  return absl::OkStatus();
}

std::string IpSecTunnel::GetDebugString() {
  return absl::Substitute("[IpSecTunnel: $0, Fd: $1]", this,
                          primary_fd_.load().value_or(-1));
}

void IpSecTunnel::StartFlushFdTimer() {
  CancelFlushFdTimerIfRunning();
  int flush_counter = ++flush_counter_;
  LOG(INFO) << "Starting Flush Fd timer " << flush_counter;
  absl::StatusOr<int> timer_id = timer_manager_->StartTimer(
      kTunnelFlushDelay,
      [this, flush_counter]() { HandleFlushFdTimerExpiry(flush_counter); },
      "FlushFdTimer");
  if (!timer_id.ok()) {
    LOG(ERROR) << "Failed to start Flush Fd timer: " << timer_id.status();
    LOG(WARNING) << "Clearing old fds now.";
    // Without the timer running to clean up the fds we should close all of the
    // old fds now, even if they have not been flushed.
    CloseNonPrimaryTunnelFds(/*skip_fds_with_data=*/false);
    return;
  }
  flush_fd_timer_id_ = *timer_id;
}

void IpSecTunnel::CancelFlushFdTimerIfRunning() {
  if (flush_fd_timer_id_) {
    LOG(INFO) << "Canceling Flush Fd timer " << flush_counter_;
    timer_manager_->CancelTimer(*flush_fd_timer_id_);
    flush_fd_timer_id_ = std::nullopt;
  }
}

void IpSecTunnel::HandleFlushFdTimerExpiry(int flush_counter) {
  absl::MutexLock lock(&mutex_);
  LOG(INFO) << "Flush Fd timer expiry " << flush_counter;
  if (!flush_fd_timer_id_) {
    LOG(INFO) << "Flush Fd timer is already cancelled.";
    return;
  }
  if (flush_counter != flush_counter_) {
    LOG(INFO) << "Ignoring old Flush Fd timer.";
    return;
  }
  flush_fd_timer_id_ = std::nullopt;
  CloseNonPrimaryTunnelFds(/*skip_fds_with_data=*/true);

  // If there are still fds left to drain start the timer again.
  if (owned_fds_.size() > 1) {
    StartFlushFdTimer();
  } else {
    LOG(INFO) << "All old tunnel fds have been flushed and closed.";
  }
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
