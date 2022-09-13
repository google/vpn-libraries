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

#include <atomic>
#include <string>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class DatagramSocket {
 public:
  explicit DatagramSocket(int fd);
  ~DatagramSocket();
  DatagramSocket(const DatagramSocket&) = delete;
  DatagramSocket(DatagramSocket&&) = delete;

  absl::Status WritePackets(std::vector<Packet> packets);

  absl::StatusOr<std::vector<Packet>> ReadPackets();

  absl::Status Close();

  std::string DebugString() { return absl::StrCat("FD=", fd_); }

  // Connects the underlying socket fd to the given endpoint.
  // This should be called before calling WritePackets.
  absl::Status Connect(const Endpoint& endpoint);

 private:
  absl::Status CreateCloseEvent();

  int fd_;
  datapath::android::EventsHelper events_helper_;
  datapath::android::EventFd shutdown_event_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_DATAGRAM_SOCKET_H_
