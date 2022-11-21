/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNPACKETTUNNELPIPE_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNPACKETTUNNELPIPE_H_

#import <NetworkExtension/NetworkExtension.h>

#include <functional>
#include <string>
#include <vector>

#include "privacy/net/krypton/pal/packet_pipe.h"
#include "third_party/absl/status/status.h"
@class PPNPacketTunnelPipeWrapper;

namespace privacy {
namespace krypton {

// An implementation of PacketPipe that's backed by an NEPacketTunnelFlow, and
// handles device-side traffic in iOS.
class PPNPacketTunnelPipe : public PacketPipe {
 public:
  explicit PPNPacketTunnelPipe(NEPacketTunnelFlow* packet_tunnel_flow);

  PPNPacketTunnelPipe(PPNPacketTunnelPipe&& other);
  PPNPacketTunnelPipe& operator=(PPNPacketTunnelPipe&& other);

  // Disallow copy and assign.
  PPNPacketTunnelPipe(const PPNPacketTunnelPipe& other) = delete;
  PPNPacketTunnelPipe& operator=(const PPNPacketTunnelPipe& other) = delete;

  absl::Status WritePackets(std::vector<Packet> packets) override;
  void ReadPackets(std::function<bool(absl::Status status, std::vector<Packet>)> handler) override;
  void Close() override;

  absl::StatusOr<int> GetFd() const override {
    return absl::UnimplementedError("NEPacketTunnelFlow does not provide a file descriptor");
  }

  std::string DebugString() override;

  /**
   * Tells the pipe to stop reading packets, and stop requesting new packets
   * from iOS. Any packets that have already been read from iOS, but have not
   * been read from the pipe, will be dropped. Once stop returns, it is
   * guaranteed that the ReadPackets handler will not be called again.
   */
  absl::Status StopReadingPackets() override;

 private:
  // The implementation is wrapped in an ARC-managed wrapper, so that it can be
  // weakly referenced, in case the read callback is called after this C++ class
  // is deleted.
  PPNPacketTunnelPipeWrapper* wrapper_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNPACKETTUNNELPIPE_H_
