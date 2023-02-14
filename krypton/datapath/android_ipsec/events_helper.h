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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_EVENTS_HELPER_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_EVENTS_HELPER_H_

#include <sys/epoll.h>

#include <string>

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// A helper to use the epoll.
// For more info refer to:
// http://man7.org/linux/man-pages/man7/epoll.7.html
class EventsHelper {
 public:
  using Event = epoll_event;

  EventsHelper();
  ~EventsHelper();

  EventsHelper(const EventsHelper&) = delete;
  EventsHelper(EventsHelper&&) = delete;

  // Registers interest in the given FD.
  // Bit mask composed by ORing together events that are interested
  // and fd is put into data field of epoll_event.
  absl::Status AddFile(int fd, unsigned int events);

  // Unregisters interest from the given FD.
  absl::Status RemoveFile(int fd);

  // Wait for new events.
  // If timeout, num_events is 0
  // If timeout_ms is 0, the call is non-blocking.
  // If timeout_ms is -1, there is no timeout.
  absl::Status Wait(Event events[], int max_events, int timeout_ms,
                    int* num_events);

  // Static methods that helps in events.

  // Returns the File Descriptor involved in the monitored event.
  static int FileFromEvent(const EventsHelper::Event& event);

  // Returns true if there is an error in the monitored event.
  static bool FileHasError(const EventsHelper::Event& event);

  // Returns true if the File Descriptor has been closed. EPOLLHUP on
  // Android/Linux allows all remaining bytes on the File Descriptor to be read
  // before returning 0.
  static bool FileWasClosed(const EventsHelper::Event& event);

  // Returns true if the event is signaling there are bytes to be read
  // from the File Descriptor.
  static bool FileCanRead(const EventsHelper::Event& event);

  // Returns true if the event is signaling that the File Descripter is
  // writable.
  static bool FileCanWrite(const EventsHelper::Event& event);

  // Returns the necessary flags to monitor file descriptors for read
  // operations.
  static inline constexpr unsigned int EventReadableFlags() {
    return EPOLLIN | EPOLLERR;
  }

  // Returns the necessary flags to monitor file descriptors for being
  // writeable.
  static inline constexpr unsigned int EventWritableFlags() {
    return EPOLLOUT | EPOLLERR;
  }

 private:
  // This is the same as above but the caller can pass a customized epoll_event.
  absl::Status AddFile(int fd, Event* ev);

  const int events_fd_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_EVENTS_HELPER_H_
