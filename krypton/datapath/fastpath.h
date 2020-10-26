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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_FASTPATH_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_FASTPATH_H_
#include <sys/socket.h>

#include <atomic>
#include <thread>  //NOLINT

#include "privacy/net/krypton/datapath/event_fd.h"
#include "privacy/net/krypton/datapath/events_helper.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {
namespace datapath {

// Class that is responsibile for reading FD data and forwarding it to the
// network and vice versa.
// This is a forwarding layer and avoid using any Mutex locks.
// This class is not thread safe.
class FastPath {
 public:
  FastPath(int tunnel_fd, int network_fd);
  ~FastPath();
  enum class Direction { UPLINK, DOWNLINK };

  // Datapath forwarder that listens on a socket forwards to the
  // destination address using UDP for uplink or posts onto a socket on
  // downlink.
  // +--------+
  // |  APP   |
  // +----+---+
  //      |
  // +----v---+      +---------+              +---------+
  // |TUN FD  +----> |NET FD   +------------> |COPPER   |
  // +--------+      +---------+              +---------+

  class Forwarder {
   public:
    Forwarder(int source_fd, int destination_fd,
              const string& destination_ip_address, int port,
              Direction direction, utils::LooperThread* looper_thread,
              DatapathInterface::NotificationInterface* datapath_notification);
    ~Forwarder();

    // |Start| needs to be called to initialize the socket reads/writes.
    absl::Status Start();

    // Stop the forwarder.
    void Stop();

   private:
    // Start of the thread.
    void Run();
    absl::Status RunInternal();
    void PostDatapathPermanentFailure(const absl::Status& status);
    void PostDatapathFailure(const absl::Status& status, int failed_fd);
    void PostDatapathEstablished();

    std::thread thread_;
    const int source_fd_;
    const int destination_fd_;
    EventsHelper events_helper_;
    utils::LooperThread* notification_thread_;  // Not owned.
    DatapathInterface::NotificationInterface*
        datapath_notification_;  // Not owned.
    // shutdown_event helps in shutting down the forwarder gracefully. Use
    // |Notify| to generate the event.
    EventFd shutdown_event_;
    sockaddr_storage destination_socket_address_;
    socklen_t destination_address_size_;
    std::string destination_address_;
    int destination_port_;
    Direction direction_;
    std::atomic_bool permanent_failure_notification_raised_ = false;
    std::atomic_bool failure_notification_raised_ = false;
    std::atomic_bool connected_notification_raised_ = false;
  };

 private:
  const Forwarder uplink_;
  const Forwarder downlink_;
};
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_FASTPATH_H_
