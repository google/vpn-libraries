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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_PACKET_FORWARDER_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_PACKET_FORWARDER_H_

#include <atomic>
#include <memory>

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/datapath/packet_forwarder.h"
#include "privacy/net/krypton/desktop/windows/datapath/wintun_tunnel.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/desktop/windows/wintun.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/socket_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

class WintunPacketForwarder {
 public:
  // Notifications for WintunPacketForwarder state changes.
  class WintunNotificationInterface {
   public:
    WintunNotificationInterface() = default;
    virtual ~WintunNotificationInterface() = default;

    // Datapath failed with status.
    // NOTE: Clients should call Stop() after receiving this notification.
    virtual void PacketForwarderFailed(const absl::Status&) = 0;
    // PacketForward did successfully forward one packet since Start is called.
    // TODO: call this notification in WintunPacketForwarder
    virtual void PacketForwarderConnected() = 0;
  };

  explicit WintunPacketForwarder(
      std::unique_ptr<datapath::ipsec::IpSecEncryptor> encryptor,
      std::unique_ptr<datapath::ipsec::IpSecDecryptor> decryptor,
      Wintun* wintun, SocketInterface* socket,
      ::privacy::krypton::utils::LooperThread* looper,
      WintunNotificationInterface* notification);
  ~WintunPacketForwarder() = default;

  // Starts processing packets coming into Wintun.
  // This changes the client's routing table to send traffic to Wintun.
  absl::Status Start();

  // Shuts down this packet forwarder by closing the network socket, ending the
  // Wintun session, and restoring the routing table to its original state.
  absl::Status Stop();

  void GetDebugInfo(DatapathDebugInfo* debug_info);

 private:
  void ProcessUplink();
  void ProcessDownlink();
  void FailWithStatus(absl::Status status);

  absl::Mutex mutex_;
  std::unique_ptr<datapath::ipsec::IpSecEncryptor> encryptor_;
  std::unique_ptr<datapath::ipsec::IpSecDecryptor> decryptor_;
  std::unique_ptr<WintunTunnel> tunnel_;
  Wintun* wintun_;                                     // Not owned.
  SocketInterface* socket_;                            // Not owned.
  krypton::utils::LooperThread* notification_thread_;  // Not owned.
  WintunNotificationInterface* notification_;          // Not owned.

  bool connected_ ABSL_GUARDED_BY(mutex_);
  bool stopped_ ABSL_GUARDED_BY(mutex_);
  krypton::utils::LooperThread uplink_looper_;
  krypton::utils::LooperThread downlink_looper_;
  std::atomic_int64_t uplink_packets_read_;
  std::atomic_int64_t downlink_packets_read_;
  std::atomic_int64_t downlink_packets_dropped_;
  std::atomic_int64_t decryption_errors_;
  std::atomic_int64_t tunnel_write_errors_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_DATAPATH_WINTUN_PACKET_FORWARDER_H_
