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

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Facilitates communication with tunnel end of datapath.
// It is unsafe to make multiple calls to ReadPackets concurrently
class IpSecTunnel : public TunnelInterface {
 public:
  static absl::StatusOr<std::unique_ptr<IpSecTunnel>> Create(int tunnel_fd);

  ~IpSecTunnel() override;
  IpSecTunnel(const IpSecTunnel&) = delete;
  IpSecTunnel(IpSecTunnel&&) = delete;

  // Closes the tunnel interface fd.
  absl::Status Close() override;

  // Stops all current reads on the tunnel, but does not close the fd.
  absl::Status CancelReadPackets() override;

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
  explicit IpSecTunnel(int tunnel_fd);

  // Performs some one-time initialization.
  absl::Status Init();

  std::atomic_int tunnel_fd_;

  EventFd close_event_;

  EventsHelper events_helper_;

  int keepalive_interval_millis_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_TUNNEL_H_
