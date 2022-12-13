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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NETWORK_MONITOR_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NETWORK_MONITOR_H_

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#include <cstdint>
#include <optional>

#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

class NetworkMonitor {
 public:
  class NotificationInterface {
   public:
    virtual ~NotificationInterface() = default;

    // Called whenever the best network changes.
    virtual void BestNetworkChanged(std::optional<NetworkInfo> network) = 0;
  };

  NetworkMonitor() = default;
  ~NetworkMonitor() = default;

  void RegisterNotificationHandler(
      NotificationInterface* notification,
      krypton::utils::LooperThread* notification_looper) {
    notification_ = notification;
    notification_looper_ = notification_looper;
  }

  // Start monitoring IP interface changes. This will monitor both v4 and v6.
  absl::Status Start();

  // Stop monitoring changes.
  void Stop();

  // Callback used by Windows to notify the monitor of changes.
  // This can be called from any thread.
  void OnInterfaceChanged(MIB_IPINTERFACE_ROW* row, MIB_NOTIFICATION_TYPE type);

 private:
  // Internal method for processing one change.
  // This should only be called on the looper_.
  void HandleInterfaceChanged(const MIB_IPINTERFACE_ROW* row,
                              MIB_NOTIFICATION_TYPE type);

  // Removes entries from network_info_ that aren't suitable for the datapath.
  // This should only be called on the looper_.
  void FilterInvalidInterfacesTypes();

  // Populates network_info_ with IP interfaces that are connected.
  // This should only be called on the looper_.
  void FetchConnectedIpInterfaces();

  // Dumps currently connected networks to LOG(INFO), for debugging.
  // This should only be called on the looper_.
  void LogCurrentNetworks();

  // Add new network to the network_info_ map.
  // This should only be called on the looper_.
  void AddNetwork(const MIB_IPINTERFACE_ROW* row);

  // Remove a network from the network_info_ map.
  // This should only be called on the looper_.
  void RemoveNetwork(int index, int family);

  // Handle a MibParameterNotification.
  // This should only be called on the looper_.
  void HandleParameterChanged(MIB_IPINTERFACE_ROW* row);

  // Selects the best network from the network_info_ map.
  // This should only be called on the looper_.
  void SelectBestNetwork();

  HANDLE notify_handle_ = nullptr;

  // These should only be accessed from the looper_.
  std::optional<int64_t> current_index_;
  std::map<int64_t, NetworkInfo> network_info_;

  // Windows calls the interface changed callback from multiple different
  // threads, and sometimes calls it multiple times simultaneously. So, by
  // putting it on a looper, we can be sure that we're only calling one callback
  // at a time.
  krypton::utils::LooperThread looper_{"Network Monitor"};

  NotificationInterface* notification_ = nullptr;
  krypton::utils::LooperThread* notification_looper_ = nullptr;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_NETWORK_MONITOR_H_
