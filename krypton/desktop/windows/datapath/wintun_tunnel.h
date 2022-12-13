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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_TUNNEL_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_TUNNEL_H_

#include <windows.h>

#include <vector>

#include "privacy/net/krypton/desktop/windows/wintun_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

// WintunTunnel represents a Wintun session.
class WintunTunnel {
 public:
  explicit WintunTunnel(WintunInterface* wintun)
      : wintun_(wintun), wintun_read_handle_(nullptr), stop_handle_(nullptr) {}
  ~WintunTunnel() {
    if (stop_handle_ != nullptr) {
      CloseHandle(stop_handle_);
    }
  }

  // Delete copy and move constructors.
  WintunTunnel(const WintunTunnel&) = delete;
  WintunTunnel(WintunTunnel&&) = delete;
  WintunTunnel& operator=(const WintunTunnel&) = delete;
  WintunTunnel& operator=(WintunTunnel&&) = delete;

  absl::Status Start();

  absl::Status StopReadingPackets();

  // Packets must be manually deallocated using Wintun::ReleaseReceivePacket.
  absl::StatusOr<std::vector<Packet>> ReadPackets();

  // Send decrypted packets to their local destinations.
  absl::Status WritePackets(std::vector<Packet> packets);

 private:
  WintunInterface* wintun_;  // Not owned.
  HANDLE wintun_read_handle_;
  HANDLE stop_handle_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_TUNNEL_H_
