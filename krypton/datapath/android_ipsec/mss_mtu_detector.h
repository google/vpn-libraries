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

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/mss_mtu_detector_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/syscall_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Obtains MTU from the TCP MSS. All the operations on the TCP socket is
// non-blocking. This class is thread-unsafe. All the member functions are
// supposed to be called within a single thread.
class MssMtuDetector : public MssMtuDetectorInterface {
 public:
  // fd: The TCP socket from which the TCP MSS will be detected.
  // tcp_mss_endpoint: the address of the TCP MSS detection server.
  // notification_interface: pointer to a notification interface to handle
  // MssMtuDetector status.
  MssMtuDetector(int fd, const Endpoint& endpoint,
                 std::unique_ptr<SyscallInterface> syscall_interface,
                 NotificationInterface* notification,
                 utils::LooperThread* notification_thread);
  ~MssMtuDetector() override;

  // Starts the MSS detection process. Will connect the socket to the server and
  // start the MSS MTU Detection in a new thread.
  void Start() override;

  // Stops the MSS detection process. If the MSS detection was not completed
  // MssMtuFailure will be called on the notification handler with an aborted
  // error.
  void Stop() override;

  // Disallow copy and assign.
  MssMtuDetector(const MssMtuDetector&) = delete;
  MssMtuDetector& operator=(const MssMtuDetector&) = delete;

 private:
  absl::Status StartInternal();
  absl::StatusOr<MssMtuUpdateInfo> HandleEventInternal(
      const EventsHelper::Event& ev);

  void HandleEvents();

  void CleanUp(bool stop_thread);

  enum class State { kUnknown, kError, kConnectStarted, kConnected, kFinished };
  static std::string StateStr(State state);
  std::string DebugString() const;

  // Marks the state as error and cleans up.
  void Error(const absl::Status& status);

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
  EventsHelper events_helper_;
  State state_ = State::kUnknown;
  bool fd_closed_ = false;
  bool sock_fd_added_to_events_ = false;
  bool stop_fd_added_to_events_ = false;

  std::unique_ptr<SyscallInterface> syscall_interface_;

  NotificationInterface* notification_;  // Not owned.

  // This thread will be used to send notifications "up the stack" to listeners.
  // It should not be used for anything else.
  utils::LooperThread* notification_thread_;  // Not owned.

  uint32_t uplink_mss_mtu_;
  uint32_t downlink_mss_mtu_;

  EventFd stop_event_;
  utils::LooperThread thread_;

  static constexpr int kDownlinkMssMtuBufferSize = 4;
  char downlink_mss_mtu_buffer_[kDownlinkMssMtuBufferSize];
  int bytes_in_buffer_ = 0;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MSS_MTU_DETECTOR_H_
