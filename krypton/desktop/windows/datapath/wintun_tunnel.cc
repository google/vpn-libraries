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

#include "privacy/net/krypton/desktop/windows/datapath/wintun_tunnel.h"

#include <utility>
#include <vector>

#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::Status WintunTunnel::Start() {
  PPN_ASSIGN_OR_RETURN(stop_handle_, utils::CreateManualResetEvent());
  wintun_read_handle_ = wintun_->GetWaitReadEvent();
  return absl::OkStatus();
}

absl::Status WintunTunnel::StopReadingPackets() {
  if (SetEvent(stop_handle_) == 0) {
    return utils::GetStatusForError("WintunTunnel", GetLastError());
  }
  return absl::OkStatus();
}

absl::StatusOr<std::vector<Packet>> WintunTunnel::ReadPackets() {
  std::vector<Packet> v;
  // We read packets in an infinite loop to ensure that we get either a packet
  // or a fatal error.
  while (true) {
    // Check if Wintun has a packet.
    auto packet = wintun_->ReceivePacket();
    if (packet.ok()) {
      v.push_back(*std::move(packet));
      return v;
    }
    // This error means Wintun doesn't have any packets, so we can ignore it.
    if (!absl::IsResourceExhausted(packet.status())) {
      return packet.status();
    }

    // Wait on handle if there's no packet.
    HANDLE handles[2] = {stop_handle_, wintun_read_handle_};
    auto result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    switch (result) {
      case WAIT_OBJECT_0 + 0: {
        // The stop handle is signaled.
        return absl::CancelledError("Cancelled wait for WintunReceivePackets");
      }
      case WAIT_OBJECT_0 + 1: {
        // The read handle is signaled, so check WintunReceivePackets again.
        continue;
      }
      default: {
        return absl::InternalError("WaitForMultipleObjects failed");
      }
    }
  }
}

absl::Status WintunTunnel::WritePackets(std::vector<Packet> packets) {
  for (Packet &packet : packets) {
    // Send packet via Wintun adapter.
    PPN_RETURN_IF_ERROR(wintun_->SendPacket(std::move(packet)));
  }
  return absl::OkStatus();
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
