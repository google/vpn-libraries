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

#include "privacy/net/krypton/desktop/windows/rio_socket.h"

#include <cstdint>
#include <utility>
#include <vector>

#include "base/init_google.h"
#include "base/logging.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/log.h"

using ::privacy::krypton::Endpoint;
using ::privacy::krypton::Packet;

// Number of packet send/receive loops.
// Default is 2 * kCompletionQueueSize to get the RIO ring buffer to overflow.
constexpr int kNumPacketLoops = 2048;

namespace {
absl::Status Main() {
  PPN_ASSIGN_OR_RETURN(
      auto src_endpoint,
      privacy::krypton::GetEndpointFromHostPort("127.0.0.1:12345"));
  PPN_ASSIGN_OR_RETURN(
      auto dst_endpoint,
      privacy::krypton::GetEndpointFromHostPort("127.0.0.1:54321"));
  int interface_index = 16;

  LOG(INFO) << "Starting RioSocket...";
  auto socket =
      privacy::krypton::windows::RioSocket(src_endpoint, interface_index);
  LOG(INFO) << "Created RioSocket";
  PPN_RETURN_IF_ERROR(socket.Open());

  PPN_RETURN_IF_ERROR(socket.Connect(dst_endpoint));
  LOG(INFO) << "RioSocket connected. Hit any key to continue...";
  auto unused = getchar();

  for (int i = 0; i < kNumPacketLoops; i++) {
    LOG(INFO) << "Loop " << i;
    std::vector<Packet> packets;
    packets.emplace_back("foo", /* sizeof("foo") */ 3,
                         privacy::krypton::IPProtocol::kIPv6, []() {});
    PPN_RETURN_IF_ERROR(socket.WritePackets(std::move(packets)));
    LOG(INFO) << "Wrote packets";

    PPN_ASSIGN_OR_RETURN(auto recv_packets, socket.ReadPackets());
    LOG(INFO) << "Read packets: " << recv_packets.size();
    for (auto& packet : recv_packets) {
      LOG(INFO) << packet.data();
    }
  }

  LOG(INFO) << "RioSocket test completed. Press any key to stop...";
  unused = getchar();
  PPN_RETURN_IF_ERROR(socket.Close());
  LOG(INFO) << "RioSocket stopped.";
  return absl::OkStatus();
}
}  // namespace

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);
  auto main_result = Main();
  if (!main_result.ok()) {
    LOG(ERROR) << main_result;
    return 1;
  }
  return 0;
}
