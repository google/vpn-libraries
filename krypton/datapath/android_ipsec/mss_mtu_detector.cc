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

#include "privacy/net/krypton/datapath/android_ipsec/mss_mtu_detector.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

std::string MssMtuDetector::StateStr(State state) {
  switch (state) {
    case State::kUnknown:
      return "UNKNOWN";
    case State::kConnectStarted:
      return "CONNECT_STARTED";
    case State::kConnected:
      return "CONNECTED";
    case State::kFinished:
      return "FINISHED";
    case State::kError:
      return "ERROR";
  }
}

MssMtuDetector::MssMtuDetector(
    int fd, const Endpoint& endpoint,
    std::unique_ptr<SyscallInterface> syscall_interface,
    NotificationInterface* notification,
    utils::LooperThread* notification_thread)
    : fd_(fd),
      endpoint_(endpoint),
      syscall_interface_(std::move(syscall_interface)),
      notification_(notification),
      notification_thread_(notification_thread),
      thread_("MSS MTU Detector Thread") {}

MssMtuDetector::~MssMtuDetector() { Stop(); }

void MssMtuDetector::Start() {
  absl::Status status = StartInternal();
  if (status.ok()) {
    thread_.Post([&]() { HandleEvents(); });
  } else {
    Error(status);
  }
}

void MssMtuDetector::Stop() { CleanUp(/*stop_thread=*/true); }

absl::Status MssMtuDetector::StartInternal() {
  absl::Status status = SetSocketNonBlocking(fd_);
  if (!status.ok()) return status;

  PPN_ASSIGN_OR_RETURN(auto sockaddr_info, endpoint_.GetSockAddr());

  // Connection on nonblocking socket cannot be completed immediately and will
  // return with the error EINPROGRESS.
  if (connect(fd_, reinterpret_cast<const sockaddr*>(&sockaddr_info.sockaddr),
              sockaddr_info.socklen) == -1 &&
      errno != EINPROGRESS) {
    return absl::InternalError(absl::StrCat("Connect TCP Socket (fd: ", fd_,
                                            ") to ", endpoint_.ToString(),
                                            " failed"));
  }

  status = events_helper_.AddFile(fd_, EventsHelper::EventWritableFlags());
  if (!status.ok()) return status;
  sock_fd_added_to_events_ = true;

  status = events_helper_.AddFile(stop_event_.fd(),
                                  EventsHelper::EventReadableFlags());
  if (!status.ok()) return status;
  stop_fd_added_to_events_ = true;

  state_ = State::kConnectStarted;
  return absl::OkStatus();
}

absl::StatusOr<MssMtuDetector::MssMtuUpdateInfo>
MssMtuDetector::HandleEventInternal(const EventsHelper::Event& ev) {
  if (EventsHelper::FileHasError(ev)) {
    std::string error_msg;
    int error = FdError(fd_, &error_msg);
    return absl::InternalError(absl::StrCat("Error event: ", error_msg, "(",
                                            error, ") ", DebugString()));
  }

  if (EventsHelper::FileWasClosed(ev)) {
    return absl::InternalError(
        absl::StrCat("server closed unexpectedly: ", DebugString()));
  }

  absl::Status status;
  if (state_ == State::kConnectStarted) {
    if (!EventsHelper::FileCanWrite(ev)) {
      return absl::InternalError(
          absl::StrCat("unexpected state: ", DebugString()));
    }
    // Socket being writable probably indicates TCP handshake is done.
    auto uplink_result_or = UpdateUplinkMssMtu();
    if (!uplink_result_or.ok()) return uplink_result_or.status();

    status = events_helper_.RemoveFile(fd_);
    if (!status.ok()) return status;
    sock_fd_added_to_events_ = false;

    state_ = State::kConnected;

    status = events_helper_.AddFile(fd_, EventsHelper::EventReadableFlags());
    if (!status.ok()) return status;
    sock_fd_added_to_events_ = true;

    return MssMtuUpdateInfo{uplink_result_or.value(),
                            UpdateResult::kNotUpdated};
  }

  if (state_ == State::kConnected) {
    if (!EventsHelper::FileCanRead(ev)) {
      return absl::InternalError(
          absl::StrCat("unexpected state: ", DebugString()));
    }
    auto downlink_result_or = UpdateDownlinkMssMtu();
    if (!downlink_result_or.ok()) return downlink_result_or.status();

    // Don't change state until all data have been received.
    if (downlink_result_or.value() == UpdateResult::kUpdated) {
      CloseFd();
      state_ = State::kFinished;
    }
    return MssMtuUpdateInfo{UpdateResult::kNotUpdated,
                            downlink_result_or.value()};
  }
  return absl::InternalError(absl::StrCat("unexpected state: ", DebugString()));
}

void MssMtuDetector::HandleEvents() {
  EventsHelper::Event event;
  int num_events;
  while (true) {
    auto status = events_helper_.Wait(&event, 1, -1, &num_events);
    if (!status.ok()) {
      Error(status);
      break;
    }
    if (EventsHelper::FileFromEvent(event) == stop_event_.fd()) {
      Error(absl::AbortedError("Stop called during MSS MTU Detection."));
      break;
    }

    auto update_info = HandleEventInternal(event);
    if (!update_info.ok()) {
      Error(update_info.status());
      break;
    }

    if (state_ == State::kFinished) {
      auto notification = notification_;
      auto uplink_mss_mtu = uplink_mss_mtu_;
      auto downlink_mss_mtu = downlink_mss_mtu_;
      notification_thread_->Post(
          [notification, uplink_mss_mtu, downlink_mss_mtu] {
            notification->MssMtuSuccess(uplink_mss_mtu, downlink_mss_mtu);
          });
      break;
    }
  }
}

void MssMtuDetector::CleanUp(bool stop_thread) {
  if (stop_fd_added_to_events_) {
    if (stop_thread) {
      PPN_LOG_IF_ERROR(stop_event_.Notify(1));
      thread_.Stop();
      thread_.Join();
    }

    PPN_LOG_IF_ERROR(events_helper_.RemoveFile(stop_event_.fd()));
    stop_fd_added_to_events_ = false;
  }

  CloseFd();
}

std::string MssMtuDetector::DebugString() const {
  return absl::Substitute(
      "state: $0, fd: $1, endpoint: $2, uplink_mss_mtu: $3, downlink_mss_mtu: "
      "$4, bytes_in_buffer: $5 ($6)",
      StateStr(state_), fd_, endpoint_.ToString(), uplink_mss_mtu_,
      downlink_mss_mtu_, bytes_in_buffer_,
      absl::BytesToHexString(absl::string_view(
          downlink_mss_mtu_buffer_, static_cast<size_t>(bytes_in_buffer_))));
}

void MssMtuDetector::CloseFd() {
  if (sock_fd_added_to_events_) {
    PPN_LOG_IF_ERROR(events_helper_.RemoveFile(fd_));
    sock_fd_added_to_events_ = false;
  }
  if (!fd_closed_) {
    shutdown(fd_, SHUT_RDWR);
    close(fd_);
    fd_closed_ = true;
  }
}

void MssMtuDetector::Error(const absl::Status& status) {
  CleanUp(/*stop_thread=*/false);
  state_ = State::kError;

  auto notification = notification_;
  notification_thread_->Post(
      [notification, status] { notification->MssMtuFailure(status); });
}

absl::StatusOr<MssMtuDetector::UpdateResult>
MssMtuDetector::UpdateUplinkMssMtu() {
  // Writable socket does not guarantee a successful connection and getsockopt
  // will not return error even without connection. If the socket is
  // connected, getpeername should succeed.
  sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  int ret = getpeername(fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len);
  if (ret != 0) {
    return absl::InternalError(absl::StrCat("getpeername failed on fd ", fd_));
  }

  uint32_t mss;
  socklen_t mss_len = sizeof(mss);
  ret = syscall_interface_->GetSockOpt(fd_, IPPROTO_TCP, TCP_MAXSEG, &mss,
                                       &mss_len);
  if (ret != 0) {
    return absl::InternalError(
        absl::StrCat("getsockopt(TCP_MAXSEG) fails on fd ", fd_));
  }
  // TODO: Make MTU derived from TCP MSS more accurate.
  // MTU calculated in this way might be too conservative.
  uplink_mss_mtu_ =
      mss + sizeof(tcphdr) +
      (endpoint_.ip_protocol() == IPProtocol::kIPv6 ? sizeof(ip6_hdr)
                                                    : sizeof(ip));
  return UpdateResult::kUpdated;
}

absl::StatusOr<MssMtuDetector::UpdateResult>
MssMtuDetector::UpdateDownlinkMssMtu() {
  int ret;
  do {
    ret = recv(fd_, downlink_mss_mtu_buffer_ + bytes_in_buffer_,
               kDownlinkMssMtuBufferSize - bytes_in_buffer_, 0);
  } while (ret == -1 && errno == EINTR);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      DLOG(INFO) << "recv would block. Wait until next readable event.";
      return UpdateResult::kNotUpdated;
    }
    return absl::InternalError(absl::StrCat("recv failed on fd ", fd_));
  }
  if (ret == 0) {
    return absl::InternalError(
        "recv returns 0. Server has closed the connection unexpectedly");
  }
  bytes_in_buffer_ += ret;
  if (bytes_in_buffer_ == kDownlinkMssMtuBufferSize) {
    // Big endian.
    downlink_mss_mtu_ = ntohl(UNALIGNED_LOAD32(downlink_mss_mtu_buffer_));
    return UpdateResult::kUpdated;
  }
  return UpdateResult::kNotUpdated;
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
