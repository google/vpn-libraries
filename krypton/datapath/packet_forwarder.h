// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_PACKET_FORWARDER_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_PACKET_FORWARDER_H_

#include <atomic>

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {

// Interface for forwarding packets between inbound packet pipe and outbound
// packet pipe.
class PacketForwarder {
 public:
  // Notification for PacketForwarder state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Datapath failed with status.
    // NOTE: Clients should call Stop() after receiving this notification.
    virtual void PacketForwarderFailed(const absl::Status&) = 0;
    // Permanent Datapath failure
    // NOTE: Clients should call Stop() after receiving this notification.
    virtual void PacketForwarderPermanentFailure(const absl::Status&) = 0;
    // PacketForward did successfully forward one packet since Start is called.
    virtual void PacketForwarderConnected() = 0;
  };

  explicit PacketForwarder(CryptorInterface* encryptor,
                           CryptorInterface* decryptor, PacketPipe* utun_pipe,
                           PacketPipe* network_pipe,
                           utils::LooperThread* looper,
                           NotificationInterface* notification);
  ~PacketForwarder() = default;

  // Whether or not the pipe has started.
  bool is_started();

  // Whether or not the pipe has shut down.
  bool is_shutdown();

  // Starts processing packets coming from the packet pipe.
  void Start();

  // Shuts down this pipe by closing the network side pipe and stopping reading
  // packets from the tunnel side pipe.
  //
  // NOTE: This method will not close the tunnel side pipe.
  void Stop();

  void GetDebugInfo(DatapathDebugInfo* debug_info);

 private:
  absl::Mutex mutex_;
  // Optional and not managed by this class.
  CryptorInterface* encryptor_;
  // Optional and not managed by this class.
  CryptorInterface* decryptor_;
  PacketPipe* utun_pipe_;
  PacketPipe* network_pipe_;
  bool started_ ABSL_GUARDED_BY(mutex_);
  bool shutdown_ ABSL_GUARDED_BY(mutex_);
  std::atomic_flag connected_;
  utils::LooperThread* notification_thread_;  // Not owned.
  NotificationInterface* notification_;       // Not owned.

  std::atomic_int64_t uplink_packets_read_;
  std::atomic_int64_t downlink_packets_read_;
  std::atomic_int64_t uplink_packets_dropped_;
  std::atomic_int64_t downlink_packets_dropped_;
  std::atomic_int64_t decryption_errors_;
};

}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_PACKET_FORWARDER_H_
