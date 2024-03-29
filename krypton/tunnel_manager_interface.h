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

#ifndef PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_INTERFACE_H_

#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {

class TunnelManagerInterface {
 public:
  virtual ~TunnelManagerInterface() = default;

  virtual absl::Status Start() = 0;

  virtual void Stop() = 0;

  virtual void SetSafeDisconnectEnabled(bool enable) = 0;

  virtual bool IsSafeDisconnectEnabled() = 0;

  virtual void DatapathStarted() = 0;

  // Creates a tunnel using the provided TunFdData. This will not create a
  // tunnel if one already exists matching the provided TunFdData, unless
  // force_tunnel_update is set.
  virtual absl::Status CreateTunnel(TunFdData tunnel_data,
                                    bool force_tunnel_update) = 0;

  // Creates a tunnel if there is no tunnel and safe disconnect is enabled.
  virtual absl::Status ResumeTunnel() = 0;

  // Creates a tunnel if there is already a tunnel. The tunnel will be created
  // using the same TunFdData as the existing tunnel.
  virtual absl::Status RecreateTunnel() = 0;

  virtual void DatapathStopped(bool force_fail_open) = 0;

  virtual bool IsTunnelActive() = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_TUNNEL_MANAGER_INTERFACE_H_
