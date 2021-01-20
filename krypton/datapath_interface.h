// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_INTERFACE_H_

#include <memory>
#include <optional>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/crypto/suite.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {

// Interface for datapath management. This is valid only for a single session,
// for recreating the session, callers need to create another instance.
class DatapathInterface {
 public:
  DatapathInterface() = default;
  virtual ~DatapathInterface() = default;

  // Notification for Datapath state changes.
  class NotificationInterface {
   public:
    NotificationInterface() = default;
    virtual ~NotificationInterface() = default;

    // Notifications.
    // Datapath is established.
    virtual void DatapathEstablished() = 0;
    // Datapath failed with status.
    // TODO: We need to figure out what to do with this when we move to
    // datapaths that don't have an fd. We can either hardcode handling in the
    // datapath itself to do the filtering, or we can have new datapaths always
    // use 0 for the failed_fd, and ignore those.
    virtual void DatapathFailed(const absl::Status&, int failed_fd) = 0;
    // Permanent Datapath failure
    virtual void DatapathPermanentFailure(const absl::Status&) = 0;
    // Datapath needs rekey
    virtual void DoRekey() = 0;
  };

  // Initialize the data path.  Start takes two parameters, the tunnel fd and
  // the egress response.
  virtual absl::Status Start(std::shared_ptr<AddEgressResponse> egress_response,
                             const BridgeTransformParams& crypto,
                             CryptoSuite suite) = 0;

  // Stop the datapath.  Callers need to clear the object and recreate after
  // |stop|.
  virtual void Stop() = 0;

  // Register for datapath status changes.
  virtual void RegisterNotificationHandler(
      DatapathInterface::NotificationInterface* notification) {
    notification_ = notification;
  }

  // nullopt for NetworkInfo indicates there are no active networks.
  // TunFd and NetworkFd ownership are borrowed from the caller, who retains
  // ownership, but guarantees them to stay alive for the life of the datapath.
  virtual absl::Status SwitchNetwork(
      uint32 session_id,
      const std::vector<std::string>& egress_point_sock_addresses,
      absl::optional<NetworkInfo> network_info,
      const PacketPipe* network_socket, const PacketPipe* tunnel,
      int counter) = 0;

  // Is datapath running or started.
  virtual bool is_running() const = 0;

  virtual absl::Status Rekey(const std::string& uplink_key,
                             const std::string& downlink_key) = 0;

 protected:
  NotificationInterface* notification_;  // Not Owned
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_INTERFACE_H_
