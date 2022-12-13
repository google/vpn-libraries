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

#include "privacy/net/krypton/desktop/windows/socket.h"

#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

constexpr int kPacketAllocSize = 1500;

absl::Status Socket::Close() {
  LOG(INFO) << "Closing Socket";
  closesocket(socket_);
  return absl::OkStatus();
}

absl::StatusOr<std::vector<Packet>> Socket::ReadPackets() {
  std::vector<Packet> v;

  // Blocking read from socket. Closing the socket will cancel this read.
  // TODO: optimize packet allocations
  char *recv_buf = new char[kPacketAllocSize];
  auto recv_bytes = recv(socket_, recv_buf, kPacketAllocSize, 0);
  if (recv_bytes == SOCKET_ERROR) {
    delete[] recv_buf;
    return utils::GetStatusForError("Socket recv failed",
                                    WSAGetLastError());
  }
  auto pkt = Packet(recv_buf, recv_bytes, IPProtocol::kIPv4,
                    [recv_buf] { delete[] recv_buf; });
  v.push_back(std::move(pkt));
  return v;
}

absl::Status Socket::WritePackets(std::vector<Packet> packets) {
  // This works if the socket is non-blocking.
  for (Packet &pkt : packets) {
    auto new_data = reinterpret_cast<const char*>(pkt.data().data());
    if (new_data == nullptr) {
      return absl::InternalError("Reinterpret cast failed");
    }
    auto result = send(socket_, new_data, pkt.data().length(), 0);
    if (result == SOCKET_ERROR) {
      return utils::GetStatusForError("socket send failed", WSAGetLastError());
    }
  }
  return absl::OkStatus();
}

absl::Status Socket::Connect(Endpoint dest) {
  PPN_ASSIGN_OR_RETURN(
      auto range, ::privacy::krypton::utils::IPRange::Parse(dest.address()));
  int port = dest.port();

  sockaddr_storage addr;
  socklen_t addr_len = 0;
  PPN_RETURN_IF_ERROR(range.GenericAddress(port, &addr, &addr_len));

  if (addr_len == 0) {
    return absl::InternalError("Got addr_size == 0.");
  }

  auto new_sockaddr = reinterpret_cast<sockaddr*>(&addr);
  if (new_sockaddr == nullptr) {
    return absl::InternalError("Reinterpret cast failed");
  }
  if (connect(socket_, new_sockaddr, addr_len) == SOCKET_ERROR) {
    return utils::GetStatusForError("socket connect failed", WSAGetLastError());
  }
  return absl::OkStatus();
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
