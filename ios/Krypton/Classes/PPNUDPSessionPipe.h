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

#ifndef GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNUDPSESSIONPIPE_H_
#define GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNUDPSESSIONPIPE_H_

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

@class PPNUDPSessionPipeWrapper;

namespace privacy {
namespace krypton {

// An implementation of PacketPipe that's backed by an NWUDPSession, and handles
// network-side traffic in iOS.
class PPNUDPSessionPipe : public PacketPipe {
 public:
  // Constructs a pipe wrapping the given session, and with the given protocol
  // to be set on both input and output packets.
  explicit PPNUDPSessionPipe(NWUDPSession* session, IPProtocol protocol);

  PPNUDPSessionPipe(PPNUDPSessionPipe&& other) = delete;
  PPNUDPSessionPipe& operator=(PPNUDPSessionPipe&& other) = delete;

  // Disallow copy and assign.
  PPNUDPSessionPipe(const PPNUDPSessionPipe& other) = delete;
  PPNUDPSessionPipe& operator=(const PPNUDPSessionPipe& other) = delete;

  // Waits for the pipe to be in the Ready state, or returns an error if the
  // pipe fails or times out while waiting.
  absl::Status WaitForReady();

  absl::Status WritePackets(std::vector<Packet> packet) override;
  void ReadPackets(std::function<bool(absl::Status status, std::vector<Packet>)> handler) override;
  void Close() override;

  absl::StatusOr<int> GetFd() const override {
    return absl::UnimplementedError("NWUDPSession does not provide a file descriptor");
  }

  absl::Status StopReadingPackets() override {
    return absl::UnimplementedError("NWUDPSession cannot be stopped");
  }

  std::string DebugString() override;

  void GetDebugInfo(PacketPipeDebugInfo* debug_info) override;

 private:
  // The implementation is wrapped in an ARC-managed wrapper, so that it can be
  // weakly referenced, in case the read callback is called after this C++ class
  // is deleted.
  PPNUDPSessionPipeWrapper* wrapper_;
};

}  // namespace krypton
}  // namespace privacy

#endif  // GOOGLEMAC_IPHONE_SHARED_PPN_KRYPTON_CLASSES_PPNUDPSESSIONPIPE_H_
