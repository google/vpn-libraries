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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_PACKET_FORWARDER_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_PACKET_FORWARDER_H_

#include <atomic>
#include <memory>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/socket_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Interface for forwarding packets between inbound packet pipe and outbound
// socket.
class IpSecPacketForwarder {
 public:
  // Notification for IpSecPacketForwarder state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Datapath failed with status.
    // NOTE: Clients should call Stop() after receiving this notification.
    virtual void IpSecPacketForwarderFailed(const absl::Status&) = 0;
    // Permanent Datapath failure
    // NOTE: Clients should call Stop() after receiving this notification.
    virtual void IpSecPacketForwarderPermanentFailure(const absl::Status&) = 0;
    // PacketForward did successfully forward one packet since Start is called.
    virtual void IpSecPacketForwarderConnected() = 0;
  };

  explicit IpSecPacketForwarder(TunnelInterface* utun_interface,
                                SocketInterface* network_socket,
                                utils::LooperThread* looper,
                                NotificationInterface* notification);
  ~IpSecPacketForwarder();

  // Whether or not the forwarder has started.
  bool is_started();

  // Whether or not the forwarder has shut down.
  bool is_shutdown();

  // Starts processing packets.
  void Start();

  // Shuts down this forwarder by closing the network side socket and stopping
  // reading packets from the tunnel side pipe.
  //
  // NOTE: This method will not close the tunnel side pipe.
  void Stop();

  void GetDebugInfo(DatapathDebugInfo* debug_info);

 private:
  void HandleDownlink();

  void WritePacketsToTun(std::vector<Packet> packets);

  void HandleUplink();

  void WritePacketsToNetwork(std::vector<Packet> packets);

  void PostDatapathFailure(const absl::Status& status);

  TunnelInterface* utun_interface_;           // Not owned.
  SocketInterface* network_socket_;           // Not owned.
  utils::LooperThread* notification_thread_;  // Not owned.
  NotificationInterface* notification_;       // Not owned.

  absl::Mutex mutex_;
  bool started_ ABSL_GUARDED_BY(mutex_);
  bool shutdown_ ABSL_GUARDED_BY(mutex_);
  std::atomic_flag connected_;

  std::atomic_int64_t uplink_packets_read_;
  std::atomic_int64_t downlink_packets_read_;
  std::atomic_int64_t uplink_packets_dropped_;
  std::atomic_int64_t downlink_packets_dropped_;

  utils::LooperThread downlink_thread_;
  utils::LooperThread uplink_thread_;

  std::atomic_bool permanent_failure_notification_raised_ = false;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_IPSEC_PACKET_FORWARDER_H_
