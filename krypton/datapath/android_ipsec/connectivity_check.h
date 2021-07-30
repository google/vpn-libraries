// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_CONNECTIVITY_CHECK_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_CONNECTIVITY_CHECK_H_
#include <sys/socket.h>

#include <thread>  // NOLINT

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace android {

// Checks the connectivity of the network to the internet.
class ConnectivityCheck {
 public:
  // Does a single connectivity check to the backend.
  ConnectivityCheck(int max_retries, int socket_fd,
                    absl::Duration connectivity_check_deadline);

  virtual ~ConnectivityCheck() = default;

  virtual absl::Status CheckUdpConnectivity(
      std::function<void(const absl::Status& status)> callback,
      absl::string_view destination_address, int destination_port);

  // Stop any pending connectivity checks and stop the ConnectivityChecks.
  // |CheckUdpConnectivity| will not work after this call.
  void Stop();

  // Cancel any pending connectivity checks. Callers can invoke new
  // connectivity checks using |CheckUdpConnectivity|.
  virtual void CancelAllConnectivityChecks();

 private:
  absl::Status CheckUdpConnectivityToCopper(
      absl::string_view destination_address, int destination_port);

  const int max_retries_;
  const int socket_fd_;
  utils::LooperThread looper_{"ConnectivityCheck"};
  // shutdown_event helps in shutting down the forwarder gracefully. Use
  // |Notify| to generate the event.
  EventFd shutdown_event_;
  absl::Duration connectivity_check_deadline_;
};

}  // namespace android
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_ANDROID_IPSEC_CONNECTIVITY_CHECK_H_
