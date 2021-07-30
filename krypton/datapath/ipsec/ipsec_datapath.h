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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_

#include <atomic>

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/datapath/packet_forwarder.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

// Manages the IPSec datapath on iOS.
//
// For IPSec datapath on Android, use datapath/android_ipsec/ipsec_datapath.
//
// This class is thread safe.
class IpSecDatapath : public DatapathInterface,
                      public datapath::PacketForwarder::NotificationInterface {
 public:
  explicit IpSecDatapath(utils::LooperThread* looper,
                         VpnServiceInterface* vpn_service)
      : notification_thread_(looper), vpn_service_(vpn_service) {}
  ~IpSecDatapath() override = default;

  // Configs the datapath.
  //
  // Datapath will not run until `SwitchNetwork` is called.
  absl::Status Start(std::shared_ptr<AddEgressResponse> egress_response,
                     const TransformParams& params) override;

  // Terminates the datapath connection.
  void Stop() override;

  // Establishes the VPN tunnel.
  absl::Status SwitchNetwork(uint32_t session_id, const Endpoint& endpoint,
                             absl::optional<NetworkInfo> network_info,
                             PacketPipe* tunnel, int counter) override;

  // Updates crypto keys.
  absl::Status SetKeyMaterials(const TransformParams& params) override;

  void PacketForwarderFailed(const absl::Status&) override;

  void PacketForwarderPermanentFailure(const absl::Status&) override;

  void PacketForwarderConnected() override;

 private:
  absl::Mutex mutex_;
  utils::LooperThread* notification_thread_;  // Not owned by this class.
  VpnServiceInterface* vpn_service_;          // Not owned by this class.
  std::unique_ptr<PacketPipe> network_socket_ ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<datapath::CryptorInterface> encryptor_
      ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<datapath::PacketForwarder> packet_forwarder_
      ABSL_GUARDED_BY(mutex_);
  std::unique_ptr<datapath::CryptorInterface> decryptor_
      ABSL_GUARDED_BY(mutex_);
  absl::optional<uint32_t> uplink_spi_ ABSL_GUARDED_BY(mutex_);
  absl::optional<TransformParams> key_material_ ABSL_GUARDED_BY(mutex_);
  absl::optional<Endpoint> endpoint_ ABSL_GUARDED_BY(mutex_);

  void ShutdownPacketForwarder();
};

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DATAPATH_H_
