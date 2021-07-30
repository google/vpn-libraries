// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/datapath/ipsec/ipsec_packet.h"

#include <cstdint>

#include "privacy/net/krypton/datapath/utils/utils.h"
#include "third_party/absl/strings/str_format.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

std::string IpSecPacket::GetDebugString(
    ssize_t max_packet_content_bytes) const {
  if (max_packet_content_bytes < 0 || max_packet_content_bytes > data_size() ||
      DEBUG_MODE) {
    max_packet_content_bytes = data_size();
  }
  // clang-format off
  std::string x =
      absl::StrCat("Packet at address ", absl::StrFormat("%p", this), ":",
             "\n Size: ", data_size());
  // clang-format on

  if (max_packet_content_bytes > 0) {
    absl::StrAppend(&x, ":", "\n",
                    utils::StringToHexASCIIDump(
                        absl::string_view(data(), max_packet_content_bytes)));
  }

  return x;
}

IPProtocol IpSecPacket::GetIPProtocol() const {
  const auto* head = reinterpret_cast<const uint8_t*>(data());

  // Look at the IP version number, which is in the first 4 bits of both IPv4
  // and IPv6 packets.
  auto version = *head >> 4;
  if (version == 4) {
    return IPProtocol::kIPv4;
  }
  if (version == 6) {
    return IPProtocol::kIPv6;
  }
  LOG(ERROR) << "Unexpected packet data";
  return IPProtocol::kUnknown;
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
