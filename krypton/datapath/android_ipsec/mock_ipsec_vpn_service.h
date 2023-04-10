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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_IPSEC_VPN_SERVICE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_IPSEC_VPN_SERVICE_H_

#include <memory>

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"
#include "privacy/net/krypton/datapath/android_ipsec/ipsec_socket_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/mtu_tracker_interface.h"
#include "privacy/net/krypton/datapath/android_ipsec/tunnel_interface.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

class MockIpSecVpnService : public IpSecDatapath::IpSecVpnServiceInterface {
 public:
  MOCK_METHOD(DatapathInterface *, BuildDatapath,
              (const KryptonConfig &, utils::LooperThread *,
               TimerManager *timer_manager),
              (override));

  MOCK_METHOD(absl::Status, CreateTunnel, (const TunFdData &), (override));

  MOCK_METHOD(void, CloseTunnel, (), (override));

  MOCK_METHOD(void, DisableKeepalive, (), (override));

  MOCK_METHOD((absl::StatusOr<std::unique_ptr<IpSecSocketInterface>>),
              CreateProtectedNetworkSocket,
              (const NetworkInfo &, const Endpoint &), (override));

  MOCK_METHOD((absl::StatusOr<std::unique_ptr<IpSecSocketInterface>>),
              CreateProtectedNetworkSocket,
              (const NetworkInfo &, const Endpoint &,
               std::unique_ptr<MtuTrackerInterface>),
              (override));

  MOCK_METHOD(TunnelInterface *, GetTunnel, (), (override));

  MOCK_METHOD(absl::Status, ConfigureIpSec, (const IpSecTransformParams &),
              (override));
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_MOCK_IPSEC_VPN_SERVICE_H_
