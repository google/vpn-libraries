// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/datapath/android_ipsec/connectivity_check.h"

#include <cstdint>
#include <cstring>

#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/proto/udp.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/random/distributions.h"
#include "third_party/absl/random/random.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {
constexpr int kMaxEvents = 4;
constexpr int kMaxBufferSize = 4098;

absl::Status ValidateUDPResponse(absl::string_view buffer,
                                 uint32_t request_id) {
  UDPResponse response;
  if (!response.ParseFromString(buffer)) {
    return absl::InvalidArgumentError("Parsing failed for UDPResponse");
  }
  if (response.request_id() != request_id) {
    return absl::FailedPreconditionError(
        "Request id does not match the response");
  }
  return absl::OkStatus();
}

}  // namespace

ConnectivityCheck::ConnectivityCheck(int max_retries, int socket_fd,
                                     absl::Duration connectivity_check_deadline)
    : max_retries_(max_retries),
      socket_fd_(socket_fd),
      connectivity_check_deadline_(connectivity_check_deadline) {}

absl::Status ConnectivityCheck::CheckUdpConnectivity(
    std::function<void(const absl::Status& status)> callback,
    absl::string_view destination_address, int destination_port) {
  looper_.Post([this, callback, destination_address, destination_port]() {
    for (int i = 0; i < max_retries_; i++) {
      auto status =
          CheckUdpConnectivityToCopper(destination_address, destination_port);
      if (status.ok()) {
        callback(absl::OkStatus());
        return;
      }
      if (status.code() == absl::StatusCode::kCancelled) {
        // request is cancelled, do not retry.
        callback(status);
        return;
      }
    }
    callback(absl::DeadlineExceededError(absl::StrCat(
        "Connectivity check failed after ", max_retries_, " attempts.")));
  });
  return absl::OkStatus();
}

void ConnectivityCheck::Stop() {
  PPN_LOG_IF_ERROR(shutdown_event_.Notify(1));
  looper_.Stop();
}

void ConnectivityCheck::CancelAllConnectivityChecks() {
  PPN_LOG_IF_ERROR(shutdown_event_.Notify(1));
}

absl::Status ConnectivityCheck::CheckUdpConnectivityToCopper(
    absl::string_view destination_address, int destination_port) {
  EventsHelper events_helper;
  EventsHelper::Event events[kMaxEvents];
  int num_events;
  sockaddr_storage destination_socket_address;
  socklen_t destination_address_size;

  auto request_id = absl::Uniform<uint32_t>(absl::BitGen(), 1, UINT32_MAX);

  PPN_ASSIGN_OR_RETURN(auto ip_range,
                       utils::IPRange::Parse(destination_address));

  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(destination_port,
                                              &destination_socket_address,
                                              &destination_address_size));

  PPN_RETURN_IF_ERROR(
      events_helper.AddFile(socket_fd_, EventsHelper::EventReadableFlags()));
  PPN_RETURN_IF_ERROR(events_helper.AddFile(
      shutdown_event_.fd(), EventsHelper::EventReadableFlags()));
  PPN_RETURN_IF_ERROR(SetSocketBlocking(socket_fd_));

  UDPRequest request;
  request.set_request_id(request_id);
  auto buffer = request.SerializeAsString();
  int ret = -1;
  do {
    ret = sendto(socket_fd_, buffer.c_str(), buffer.size(), MSG_CONFIRM,
                 reinterpret_cast<sockaddr*>(&destination_socket_address),
                 destination_address_size);
  } while (ret == -1 && errno == EINTR);
  if (ret == -1) {
    LOG(INFO) << "Send failed";
    return FdError(absl::StatusCode::kDeadlineExceeded, socket_fd_);
  }

  PPN_RETURN_IF_ERROR(events_helper.Wait(
      events, kMaxEvents, connectivity_check_deadline_ / absl::Milliseconds(1),
      &num_events));
  if (num_events == 0) {
    return absl::DeadlineExceededError("Timeout on Connectivity check");
  }
  VLOG(3) << "Received events";
  for (int i = 0; i < num_events; ++i) {
    int notified_fd = EventsHelper::FileFromEvent(events[i]);
    if (notified_fd == shutdown_event_.fd()) {
      LOG(INFO) << "Shutting down connectivity check";
      return absl::CancelledError("Connectivity check is cancelled");
    }

    if (EventsHelper::FileHasError(events[i])) {
      return absl::DataLossError(absl::Substitute("Reading from FD $0: $1",
                                                  socket_fd_, strerror(errno)));
    }
    int read_bytes;
    char buffer[kMaxBufferSize];
    memset(buffer, 0, kMaxBufferSize);
    do {
      read_bytes = read(notified_fd, &buffer, kMaxBufferSize);
    } while (read_bytes == -1 && errno == EINTR);

    if (read_bytes <= 0) {
      return absl::DataLossError(absl::Substitute("Reading from FD $0: $1",
                                                  socket_fd_, strerror(errno)));
    }
    PPN_RETURN_IF_ERROR(ValidateUDPResponse(buffer, request_id));
  }

  return absl::OkStatus();
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
