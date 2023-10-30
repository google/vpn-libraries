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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_TUNNEL_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_TUNNEL_H_

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/timer_manager.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Facilitates communication with tunnel end of datapath.
// It is unsafe to make multiple calls to ReadPackets concurrently
class IpSecTunnel : public TunnelInterface {
 public:
  // Closes the tunnel_fd if the create fails
  static absl::StatusOr<std::unique_ptr<IpSecTunnel>> Create(
      int tunnel_fd, TimerManager* timer_manager);

  ~IpSecTunnel() override;
  IpSecTunnel(const IpSecTunnel&) = delete;
  IpSecTunnel(IpSecTunnel&&) = delete;

  // Clears any previous cancel read events.
  absl::Status Reset() override;

  // Takes ownership of the fd and begins using it for reads and writes. Fds
  // already owned will be closed after a period of time to allow any in flight
  // data to arrive.
  absl::Status AdoptFd(int fd) ABSL_LOCKS_EXCLUDED(mutex_);

  // Stops all current reads on the tunnel and closes all fds currently owned by
  // the tunnel.
  void Close() ABSL_LOCKS_EXCLUDED(mutex_);

  // Stops all current reads on the tunnel, but does not close the fd.
  void CancelReadPackets() override;

  // Reads packets from the tunnel interface.
  absl::StatusOr<std::vector<Packet>> ReadPackets() override;

  // Writes packets to the tunnel interface.
  absl::Status WritePackets(std::vector<Packet> packets) override;

  // Set the keepalive interval. This should not be called if there are any
  // calls to ReadPackets currently blocking.
  void SetKeepaliveInterval(absl::Duration keepalive_interval);

  // Get the current value of the keepalive interval.
  absl::Duration GetKeepaliveInterval();

  // Test if the keepalive is enabled.
  bool IsKeepaliveEnabled();

 protected:
  explicit IpSecTunnel(TimerManager* timer_manager);

  // Performs some one-time initialization.
  absl::Status Init();

  // Checks if the provided tunnel fd still has data to read.
  bool TunnelFdHasData(int fd);

  // Closes the provided fd and removes it from the EventsHelper.
  void CloseTunnelFd(int fd);

  // Closes all non-primary tunnel fds.
  void CloseNonPrimaryTunnelFds(bool skip_fds_with_data)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Reads all events from the provided EventFd.
  absl::Status ClearEventFd(const EventFd& event_fd);

  // Returns a string representation of the tunnel.
  std::string GetDebugString();

  void StartFlushFdTimer() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CancelFlushFdTimerIfRunning() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void HandleFlushFdTimerExpiry(int flush_counter) ABSL_LOCKS_EXCLUDED(mutex_);

 private:
  absl::Mutex mutex_;

  // The primary fd cannot be guarded by a mutex due to performance issues.
  std::atomic<std::optional<int>> primary_fd_;
  std::vector<int> owned_fds_ ABSL_GUARDED_BY(mutex_);
  std::optional<int> flush_fd_timer_id_ ABSL_GUARDED_BY(mutex_);
  int flush_counter_ ABSL_GUARDED_BY(mutex_);
  EventFd cancel_read_event_;
  EventsHelper events_helper_;
  int keepalive_timeout_ms_;

  TimerManager* timer_manager_;  // Not owned.
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_TUNNEL_H_
