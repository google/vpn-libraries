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

#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"

#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "base/logging.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {
namespace {

int CreateEventsFd() {
  int fd = epoll_create(1);
  CHECK(fd >= 0) << "CreateEpollFd() failed: " << strerror(errno);
  return fd;
}

}  // namespace

EventsHelper::EventsHelper() : events_fd_(CreateEventsFd()) {}
EventsHelper::~EventsHelper() { close(events_fd_); }

::absl::Status EventsHelper::AddFile(int fd, unsigned int events) {
  Event event{};
  event.events = events;
  event.data.fd = fd;
  return AddFile(fd, &event);
}

::absl::Status EventsHelper::AddFile(int fd, Event* ev) {
  int ret = epoll_ctl(events_fd_, EPOLL_CTL_ADD, fd, ev);

  if (ret != 0) {
    return ::absl::InternalError(
        absl::StrCat("AddFile EPOLL_CTL_ADD/EV_ADD: ", strerror(errno)));
  }
  return ::absl::OkStatus();
}

::absl::Status EventsHelper::RemoveFile(int fd) {
  int ret = epoll_ctl(events_fd_, EPOLL_CTL_DEL, fd, nullptr);
  if (ret != 0) {
    return ::absl::InternalError(
        absl::StrCat("RemoveFile EPOLL_CTL_DEL/EV_DELETE: ", strerror(errno)));
  }
  return ::absl::OkStatus();
}

::absl::Status EventsHelper::Wait(Event events[], int max_events,
                                  int timeout_ms, int* num_events) {
  int num;
  do {
    num = epoll_wait(events_fd_, events, max_events, timeout_ms);
  } while (num < 0 && errno == EINTR);
  if (num < 0) {
    return absl::InternalError(absl::StrCat("epoll_wait: ", strerror(errno)));
  }
  *num_events = num;
  return ::absl::OkStatus();
}

int EventsHelper::FileFromEvent(const EventsHelper::Event& event) {
  return event.data.fd;
}

bool EventsHelper::FileHasError(const EventsHelper::Event& event) {
  return (event.events & EPOLLERR) != 0u;
}

bool EventsHelper::FileWasClosed(const EventsHelper::Event& event) {
  return (event.events & EPOLLHUP) != 0u;
}

bool EventsHelper::FileCanRead(const EventsHelper::Event& event) {
  return (event.events & EPOLLIN) != 0u;
}

bool EventsHelper::FileCanWrite(const EventsHelper::Event& event) {
  return (event.events & EPOLLOUT) != 0u;
}

std::string EventsHelper::EventStr(const EventsHelper::Event& event) {
  unsigned int events = event.events;
  return absl::StrCat((events & EPOLLIN) != 0u ? "IN " : "",
                      (events & EPOLLOUT) != 0u ? "OUT " : "",
                      (events & EPOLLERR) != 0u ? "ERR " : "",
                      (events & EPOLLHUP) != 0u ? "HANGUP " : "");
}

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
