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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_DATAGRAM_SOCKET_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_DATAGRAM_SOCKET_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class DatagramSocket : public IpSecSocketInterface {
 public:
  // Creates a DatagramSocket without path MTU discovery enabled.
  static absl::StatusOr<std::unique_ptr<DatagramSocket>> Create(int socket_fd);

  // Creates a DatagramSocket with path MTU discovery enabled. The provided
  // MtuTrackerInterface object will be used to keep track of the currently
  // known path MTU information.
  static absl::StatusOr<std::unique_ptr<DatagramSocket>> Create(
      int socket_fd, std::unique_ptr<MtuTrackerInterface>);

  ~DatagramSocket() override;
  DatagramSocket(const DatagramSocket&) = delete;
  DatagramSocket(DatagramSocket&&) = delete;

  absl::Status Close() override;

  absl::Status CancelReadPackets() override;

  absl::StatusOr<std::vector<Packet>> ReadPackets() override;

  absl::Status WritePackets(std::vector<Packet> packets) override;

  // Connects the underlying socket fd to the given endpoint.
  // This should be called before calling WritePackets.
  absl::Status Connect(Endpoint dest) override;

  int GetFd() override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override;

  std::string DebugString();

 private:
  explicit DatagramSocket(int socket_fd);

  absl::Status Init();

  absl::Status ClearEventFd(int fd);

  absl::Status EnablePathMtuDiscovery(
      std::unique_ptr<MtuTrackerInterface> mtu_tracker);

  absl::Status UpdateMtuFromKernel(IPProtocol ip_protocol);

  absl::Status ProcessSocketErrorQueue() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  absl::Mutex mutex_;  // Ensures kernel_mtu_ contains the most recent MTU read
                       // from the socket error queue

  std::atomic_int socket_fd_;

  EventFd cancel_read_event_;
  EventsHelper events_helper_;

  bool dynamic_mtu_enabled_;
  std::atomic_int uplink_packets_dropped_;
  int kernel_mtu_ ABSL_GUARDED_BY(mutex_);

  // Only accessed from Connect and WritePackets functions
  std::unique_ptr<MtuTrackerInterface> mtu_tracker_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_DATAGRAM_SOCKET_H_
