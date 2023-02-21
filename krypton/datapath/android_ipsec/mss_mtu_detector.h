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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_H_

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/syscall_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Obtains MTU from the TCP MSS. All the operations on the TCP socket is
// non-blocking. This class is thread-unsafe. All the member functions are
// supposed to be called within a single thread.
class MssMtuDetector {
 public:
  // fd: The TCP socket from which the TCP MSS will be detected.
  // tcp_mss_endpoint: the address of the TCP MSS detection server.
  // notification_interface: pointer to a notification interface to handle
  // MssMtuDetector status.
  MssMtuDetector(int fd, const Endpoint& endpoint, EventsHelper* events_helper,
                 std::unique_ptr<SyscallInterface> syscall_interface);
  virtual ~MssMtuDetector();

  virtual std::optional<uint32> uplink_mss_mtu() const {
    return uplink_mss_mtu_;
  }
  virtual std::optional<uint32> downlink_mss_mtu() const {
    return downlink_mss_mtu_;
  }
  // Starts the MSS detection process. Will connect the socket to the server and
  // register it to events helper. Must be called before HandleEvent().
  virtual absl::Status Start();

  enum class UpdateResult { kUpdated, kNotUpdated };
  struct MssMtuUpdateInfo {
    UpdateResult uplink;
    UpdateResult downlink;
  };

  // Handles the file events that are reported for the corresponding TCP socket
  // file descriptor. Returns whether the uplink and downlink MSS MTU have been
  // updated.
  virtual absl::StatusOr<MssMtuUpdateInfo> HandleEvent(
      const EventsHelper::Event& ev);

  // Disallow copy and assign.
  MssMtuDetector(const MssMtuDetector&) = delete;
  MssMtuDetector& operator=(const MssMtuDetector&) = delete;

 private:
  absl::Status StartInternal();
  absl::StatusOr<MssMtuUpdateInfo> HandleEventInternal(
      const EventsHelper::Event& ev);

  enum class State { kUnknown, kError, kConnectStarted, kConnected, kFinished };
  static std::string StateStr(State state);
  std::string DebugString() const;

  // Marks the state as error and cleans up.
  void Error();

  // Closes the socket if not closed yet and unregisters it from the events
  // helper if not unregistered. It is safe to call this function multiple
  // times.
  void CloseFd();

  absl::StatusOr<UpdateResult> UpdateUplinkMssMtu();
  absl::StatusOr<UpdateResult> UpdateDownlinkMssMtu();

  // File descriptor of the TCP socket. This class is responsible for closing it
  // when there is an error or the MSS detection has finished. Make sure not to
  // close the fd multiple times to prevent closing another file that reuses the
  // same fd.
  const int fd_;
  // Dataplane address of server.
  const Endpoint endpoint_;
  EventsHelper* const events_helper_;
  State state_ = State::kUnknown;
  bool fd_closed_ = false;
  bool added_to_events_helper_ = false;

  std::unique_ptr<SyscallInterface> syscall_interface_;

  std::optional<uint32> uplink_mss_mtu_;
  std::optional<uint32> downlink_mss_mtu_;

  static constexpr int kDownlinkMssMtuBufferSize = 4;
  char downlink_mss_mtu_buffer_[kDownlinkMssMtuBufferSize];
  int bytes_in_buffer_ = 0;

  friend class MssMtuDetectorTest;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_H_
