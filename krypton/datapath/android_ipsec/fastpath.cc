// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/datapath/android_ipsec/fastpath.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <thread>  //NOLINT

#include "base/logging.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/socket_util.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {
constexpr int kMaxPacketSize = 4096;
constexpr int kMaxEvents = 4;

}  // namespace

FastPath::Forwarder::Forwarder(
    int source_fd, int destination_fd,
    const std::string& destination_ip_address, int port, Direction direction,
    utils::LooperThread* looper_thread,
    DatapathInterface::NotificationInterface* datapath_notification)
    : source_fd_(source_fd),
      destination_fd_(destination_fd),
      notification_thread_(looper_thread),
      datapath_notification_(datapath_notification),
      destination_address_(destination_ip_address),
      destination_port_(port),
      direction_(direction) {}

absl::Status FastPath::Forwarder::Start() {
  PPN_ASSIGN_OR_RETURN(auto ip_range,
                       utils::IPRange::Parse(destination_address_));

  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(destination_port_,
                                              &destination_socket_address_,
                                              &destination_address_size_));
  thread_ = std::thread(absl::bind_front(&FastPath::Forwarder::Run, this));
  return absl::OkStatus();
}

FastPath::Forwarder::~Forwarder() {
  auto shutdown_status = shutdown_event_.Notify(1);
  if (!shutdown_status.ok()) {
    LOG(ERROR) << shutdown_status;
  }
  if (thread_.joinable()) {
    LOG(INFO) << "Joining forwarder thread.";
    thread_.join();
  }
}

void FastPath::Forwarder::Run() {
  auto status = RunInternal();
  if (!status.ok()) {
    PostDatapathPermanentFailure(status);
  }
}

absl::Status FastPath::Forwarder::RunInternal() {
  LOG(INFO) << "Starting forwarder for source_fd:" << source_fd_
            << " destination_fd:" << destination_fd_
            << " to destination address:" << destination_address_ << ":"
            << destination_port_;

  auto make_cleanup = absl::MakeCleanup([this]() {
    LOG(INFO) << "Exiting forwarder for source_fd:" << source_fd_
              << " destination_fd:" << destination_fd_
              << " to destination address:" << destination_address_ << ":"
              << destination_port_;
  });

  // Build the event fd with source_fd & shutdown_fd
  PPN_RETURN_IF_ERROR(
      events_helper_.AddFile(source_fd_, EventsHelper::EventReadableFlags()));
  PPN_RETURN_IF_ERROR(events_helper_.AddFile(
      shutdown_event_.fd(), EventsHelper::EventReadableFlags()));
  PPN_RETURN_IF_ERROR(SetSocketBlocking(source_fd_));

  EventsHelper::Event events[kMaxEvents];
  while (true) {
    int num_events = 0;
    auto status = events_helper_.Wait(events, kMaxEvents, -1, &num_events);
    VLOG(3) << "Received events";
    if (!status.ok()) {
      PostDatapathFailure(status);
      continue;
    }

    VLOG(3) << "Num Events received " << num_events;
    for (int i = 0; i < num_events; ++i) {
      int notified_fd = EventsHelper::FileFromEvent(events[i]);
      if (notified_fd == shutdown_event_.fd()) {
        LOG(INFO) << "Shutting down forwarder";
        return absl::OkStatus();
      }
      if (EventsHelper::FileHasError(events[i])) {
        PostDatapathFailure(FdError(absl::StatusCode::kDataLoss, source_fd_));
        continue;
        // continue reading from socket in case there might be data.
      }
      if (EventsHelper::FileCanRead(events[i])) {
        char buffer[kMaxPacketSize];
        int read_bytes;
        do {
          read_bytes = read(notified_fd, &buffer, kMaxPacketSize);
        } while (read_bytes == -1 && errno == EINTR);

        if (read_bytes <= 0) {
          PostDatapathFailure(absl::DataLossError(absl::Substitute(
              "Reading from FD $0: $1", source_fd_, strerror(errno))));
          continue;
        }
        int write_bytes;
        do {
          write_bytes =
              sendto(destination_fd_, buffer, read_bytes, MSG_CONFIRM,
                     reinterpret_cast<sockaddr*>(&destination_socket_address_),
                     destination_address_size_);
        } while (write_bytes == -1 && errno == EINTR);
        if (write_bytes == -1) {
          PostDatapathFailure(
              FdError(absl::StatusCode::kPermissionDenied, destination_fd_));
        }
      }
    }
  }
  return absl::OkStatus();
}

void FastPath::Forwarder::Stop() {
  auto shutdown_status = shutdown_event_.Notify(1);
  if (!shutdown_status.ok()) {
    PostDatapathPermanentFailure(shutdown_status);
  }
}

void FastPath::Forwarder::PostDatapathPermanentFailure(
    const absl::Status& status) {
  if (permanent_failure_notification_raised_) {
    LOG(ERROR) << "Datapath permanent failure [Dedup]:" << status;
    return;
  }
  LOG(ERROR) << "Datapath permanent failure " << status;
  auto* notification = datapath_notification_;
  notification_thread_->Post([notification, status]() {
    notification->DatapathPermanentFailure(status);
  });
  permanent_failure_notification_raised_ = true;
}

void FastPath::Forwarder::PostDatapathFailure(const absl::Status& status) {
  if (failure_notification_raised_) {
    LOG(ERROR) << "Datapath failure [Dedup] " << status;
    return;
  }
  LOG(ERROR) << "Datapath failure " << status;
  auto* notification = datapath_notification_;
  notification_thread_->Post(
      [notification, status]() { notification->DatapathFailed(status); });
  failure_notification_raised_ = true;
}

void FastPath::Forwarder::PostDatapathEstablished() {
  if (connected_notification_raised_) {
    LOG(INFO) << "Datapath connected [Dedup]";
    return;
  }
  LOG(INFO) << "Datapath connected";
  auto* notification = datapath_notification_;
  notification_thread_->Post(
      [notification]() { notification->DatapathEstablished(); });
  connected_notification_raised_ = true;
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
