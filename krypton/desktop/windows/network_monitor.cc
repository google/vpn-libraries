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

#include "privacy/net/krypton/desktop/windows/network_monitor.h"

#include <cstdint>
#include <memory>
#include <optional>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/networking.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/desktop/windows/xenon/network_debug.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"

namespace privacy {
namespace krypton {
namespace windows {

// TODO: add automated tests for NetworkMonitor logic

// Tells the global network context monitor context that this reference to the
// monitor is no longer needed.
void ReleaseNetworkMonitorReference(NetworkMonitor *monitor);

// A smart pointer to a NetworkMonitor that tells the global network context
// monitor when its deleted, rather than freeing the memory.
typedef std::unique_ptr<NetworkMonitor,
                        decltype(&ReleaseNetworkMonitorReference)>
    NetworkMonitorPtr;

/**
 * Singleton object that keeps track of pointers to NetworkMonitor.
 *
 * This is needed because the Windows APIs for monitoring network interface
 * changes are old school C functions that just take a function pointer and a
 * context pointer as a parameter. The callback happens on an unspecified
 * background thread. And the function to stop calling the callback makes no
 * guarantees about when it's actually finished. So in order to access the
 * calling object safely, we have to have a singleton that is never deallocated.
 *
 * Rather than keeping the whole network monitor in memory, we just keep this
 * context object in memory. It keeps track of the current NetworkMonitor, and
 * guarantees that when Stop returns, no other thread has a pointer to it.
 */
class NetworkMonitorContext {
 public:
  // Sets the monitor to be used by the callback.
  absl::Status Start(NetworkMonitor *monitor);

  // Grabs a smart pointer to NetworkMonitor, which will be released when done.
  NetworkMonitorPtr Borrow();

  // Decrements the retain count. Should only be called by the smart pointer.
  void Release();

  // Waits until all references have been released and clears them.
  void Stop();

 private:
  absl::Mutex mutex_;
  NetworkMonitor *monitor_ ABSL_GUARDED_BY(mutex_);
  int retain_count_ ABSL_GUARDED_BY(mutex_);
  absl::CondVar retain_count_decremented_;
};

// This is the global instance of NetworkMonitorContext. It is never deleted.
NetworkMonitorContext *global_network_monitor_context =
    new NetworkMonitorContext();

void ReleaseNetworkMonitorReference(NetworkMonitor *monitor) {
  if (monitor != nullptr) {
    global_network_monitor_context->Release();
  }
}

absl::Status NetworkMonitorContext::Start(NetworkMonitor *monitor) {
  absl::MutexLock lock(&mutex_);
  if (monitor_ != nullptr) {
    return absl::FailedPreconditionError("monitor_ != nullptr");
  }
  monitor_ = monitor;
  retain_count_ = 0;
  return absl::OkStatus();
}

NetworkMonitorPtr NetworkMonitorContext::Borrow() {
  absl::MutexLock lock(&mutex_);
  if (monitor_ == nullptr) {
    return NetworkMonitorPtr(nullptr, ReleaseNetworkMonitorReference);
  }
  retain_count_++;
  return NetworkMonitorPtr(monitor_, ReleaseNetworkMonitorReference);
}

// Decrements the retain count.
void NetworkMonitorContext::Release() {
  {
    absl::MutexLock lock(&mutex_);
    retain_count_--;
  }
  retain_count_decremented_.SignalAll();
}

// Waits until all references have been released and clears them.
void NetworkMonitorContext::Stop() {
  absl::MutexLock lock(&mutex_);
  while (retain_count_ != 0) {
    retain_count_decremented_.Wait(&mutex_);
  }
  monitor_ = nullptr;
}

/*
 * Global callback that is called by a background thread and gets the current
 * NetworkMonitor from the global network monitor context, before invoking the
 * callback instance method.
 *
 * Note: The row passed in here may be null if type==MibInitialNotification.
 */
void InterfaceChanged(void* context, MIB_IPINTERFACE_ROW* row,
                      MIB_NOTIFICATION_TYPE type) {
  auto monitor = global_network_monitor_context->Borrow();
  if (monitor == nullptr) {
    LOG(INFO) << "Skipping InterfaceChanged callback, because stopped.";
    return;
  }

  if (row == nullptr && type != MibInitialNotification) {
    LOG(ERROR) << "Got unexpected null row in interface change callback.";
    return;
  }

  switch (type) {
    case MibParameterNotification:
      LOG(INFO) << "Received parameter change notification for interface "
                << row->InterfaceIndex;
      break;
    case MibAddInstance:
      LOG(INFO) << "New IpInterfaceRow added on interface "
                << row->InterfaceIndex;
      break;
    case MibDeleteInstance:
      LOG(INFO) << "IpInterfaceRow deleted on interface "
                << row->InterfaceIndex;
      break;
    case MibInitialNotification:
      LOG(INFO) << "Initial notification for interface changes";
      break;
  }

  monitor->OnInterfaceChanged(row, type);
}

absl::Status NetworkMonitor::Start() {
  // Reset current_index_ so that Krypton always gets a network on the next
  // HandleInterfaceChanged call.
  current_index_.reset();
  PPN_RETURN_IF_ERROR(global_network_monitor_context->Start(this));

  HANDLE notify_handle;
  auto result = NotifyIpInterfaceChange(AF_UNSPEC, &InterfaceChanged, nullptr,
                                        true, &notify_handle);
  if (result != NO_ERROR) {
    return utils::GetStatusForError("NotifyIpInterfaceChange failed", result);
  }
  notify_handle_ = notify_handle;
  return absl::OkStatus();
}

void NetworkMonitor::Stop() {
  global_network_monitor_context->Stop();

  if (notify_handle_ == nullptr) {
    LOG(ERROR) << "Network monitor stopped without a notification handle";
  }

  auto notify_handle = notify_handle_;
  // CancelMibChangeNotify2 cannot be called from same thread as
  // NotificationCallback i.e. OnInterfaceChanged.
  notification_looper_->Post([notify_handle] {
    auto result = CancelMibChangeNotify2(notify_handle);
    if (result != NO_ERROR) {
      LOG(ERROR) << utils::GetStatusForError("CancelMibChangeNotify2 failed",
                                             result);
    }
  });
  LOG(INFO) << "NetworkMonitor stopped";
}

void NetworkMonitor::OnInterfaceChanged(MIB_IPINTERFACE_ROW* row,
                                        MIB_NOTIFICATION_TYPE type) {
  MIB_IPINTERFACE_ROW new_row;
  if (row != nullptr) {
    new_row.Family = row->Family;
    new_row.InterfaceLuid = row->InterfaceLuid;
    new_row.InterfaceIndex = row->InterfaceIndex;
  }
  looper_.Post(
      [this, new_row, type]() { HandleInterfaceChanged(&new_row, type); });
}

void NetworkMonitor::FilterInvalidInterfacesTypes() {
  PMIB_IF_TABLE2 table;
  auto result = GetIfTable2(&table);
  if (result != ERROR_SUCCESS) {
    auto status = utils::GetStatusForError(
        "GetIfTable2 failed in NetworkMonitor callback", result);
    LOG(ERROR) << status;
    return;
  }
  auto free_table = absl::MakeCleanup([table]() { FreeMibTable(table); });

  for (int i = 0; i < table->NumEntries; i++) {
    uint64_t id = table->Table[i].InterfaceIndex;

    if (network_info_.find(id) == network_info_.end()) {
      continue;
    }

    // The loopback interface should never count.
    if (table->Table[i].Type == IF_TYPE_SOFTWARE_LOOPBACK) {
      LOG(INFO) << "Removing loopback interface " << id;
      network_info_.erase(id);
      continue;
    }

    // This is so we don't try to establish the VPN through an existing VPN.
    if (table->Table[i].Type == IF_TYPE_PROP_VIRTUAL) {
      LOG(INFO) << "Removing virtual interface " << id;
      network_info_.erase(id);
      continue;
    }

    // Tunnel interfaces are usually for IPv6 compatibility.
    // But PPN can use IPv4, so it doesn't need to go through another tunnel.
    if (table->Table[i].Type == IF_TYPE_TUNNEL) {
      LOG(INFO) << "Removing tunnel interface " << id;
      network_info_.erase(id);
      continue;
    }

    // Fill in the network type.
    NetworkInfo& network_info = network_info_[id];
    switch (table->Table[i].Type) {
      case IF_TYPE_ETHERNET_CSMACD:
        network_info.set_network_type(ETHERNET);
        break;
      case IF_TYPE_IEEE80211:
        network_info.set_network_type(WIFI);
        break;
      default:
        LOG(WARNING) << "Unhandled network type " << table->Table[i].Type;
    }
  }
}

void NetworkMonitor::FetchConnectedIpInterfaces() {
  PMIB_IPINTERFACE_TABLE table;
  auto result = GetIpInterfaceTable(AF_UNSPEC, &table);
  if (result != ERROR_SUCCESS) {
    auto status = utils::GetStatusForError(
        "GetIpInterfaceTable failed in NetworkMonitor callback", result);
    LOG(ERROR) << status;
    return;
  }
  auto free_table = absl::MakeCleanup([table]() { FreeMibTable(table); });

  for (int i = 0; i < table->NumEntries; i++) {
    int64_t id = table->Table[i].InterfaceIndex;

    if (!table->Table[i].Connected) {
      LOG(INFO) << "Skipping interface " << id
                << " because it is not connected.";
      continue;
    }
    LOG(INFO) << "Considering connected IP interface " << id;
    AddNetwork(&table->Table[i]);
  }
}

void NetworkMonitor::LogCurrentNetworks() {
  LOG(INFO) << "Current networks:";
  for (const auto& [id, network] : network_info_) {
    LOG(INFO) << xenon::GetNetworkInfoDebugString(network);
  }
}

// Compares two network types for preference in establishing a connection.
// Returns -1 if type1 is worse, +1 if type1 is better, or 0 if the same.
int CompareNetworkTypes(NetworkType type1, NetworkType type2) {
  if (type1 == type2) {
    return 0;
  }
  // Ethernet is always preferred.
  if (type1 == ETHERNET) {
    return 1;
  }
  if (type2 == ETHERNET) {
    return -1;
  }
  // Neither is Ethernet. How about WiFi?
  if (type1 == WIFI) {
    return 1;
  }
  if (type2 == WIFI) {
    return -1;
  }
  // Neither is Ethernet or WiFi, so we don't have a preference.
  return 0;
}

// Returns true if network1 is better than network2, by some heuristics.
bool IsBetterNetwork(const NetworkInfo& network1, const NetworkInfo& network2) {
  int type_comparison =
      CompareNetworkTypes(network1.network_type(), network2.network_type());
  if (type_comparison != 0) {
    return type_comparison > 0;
  }

  // Neither type is better, so fall back to a stable tie-breaker.
  return network1.network_id() < network2.network_id();
}

void NetworkMonitor::HandleInterfaceChanged(const MIB_IPINTERFACE_ROW* row,
                                            MIB_NOTIFICATION_TYPE type) {
  int index = 0;
  if (row != nullptr) {
    index = row->InterfaceIndex;
  }
  switch (type) {
    case MibParameterNotification: {
      // Get the row, as NotifyIpInterfaceChange doesn't give us full info.
      MIB_IPINTERFACE_ROW row2;
      InitializeIpInterfaceEntry(&row2);
      row2.InterfaceLuid = row->InterfaceLuid;
      row2.InterfaceIndex = index;
      row2.Family = row->Family;
      int result = GetIpInterfaceEntry(&row2);
      if (result != NO_ERROR) {
        LOG(INFO) << "GetIpInterfaceEntry failed: " << result;
      }

      HandleParameterChanged(&row2);
      break;
    }
    case MibAddInstance: {
      // Add a new row mapping to our table if the interface is connected.
      if (row->Connected) {
        AddNetwork(row);
      }
      break;
    }
    case MibDeleteInstance: {
      RemoveNetwork(index, row->Family);
      break;
    }
    case MibInitialNotification: {
      // Populate our table.
      FetchConnectedIpInterfaces();
      LogCurrentNetworks();
      break;
    }
  }
  FilterInvalidInterfacesTypes();
  SelectBestNetwork();
}

void NetworkMonitor::AddNetwork(const MIB_IPINTERFACE_ROW* row) {
  auto index = row->InterfaceIndex;
  NetworkInfo network_info;
  network_info.set_network_id(index);

  // Do a connectivity check to ensure that the interface is usable.
  auto result = utils::InterfaceConnectivityCheck(index, row->Family);
  if (!result.ok()) {
    LOG(ERROR) << "Interface " << index
               << " failed connectivity check: " << result;
    return;
  }

  // Add or update NetworkInfo in the map.
  if (row->Family == AF_INET) {
    // If there's already info for this interface, modify the existing info.
    if (network_info_.find(index) != network_info_.end() &&
        network_info_[index].address_family() == NetworkInfo::V6) {
      network_info_[index].set_address_family(NetworkInfo::V4V6);
      LOG(INFO) << "Interface " << index << " is now V4V6 from V4.";
      return;
    }
    network_info.set_address_family(NetworkInfo::V4);
  } else if (row->Family == AF_INET6) {
    if (network_info_.find(index) != network_info_.end() &&
        network_info_[index].address_family() == NetworkInfo::V4) {
      network_info_[index].set_address_family(NetworkInfo::V4V6);
      LOG(INFO) << "Interface " << index << " is now V4V6 from V6.";
      return;
    }
    network_info.set_address_family(NetworkInfo::V6);
  }
  network_info_[index] = network_info;
  LOG(INFO) << "Added interface " << index << " to list.";
}

void NetworkMonitor::RemoveNetwork(int index, int family) {
  if (network_info_.find(index) == network_info_.end()) {
    LOG(ERROR) << "Can't remove index, not in network map: " << index;
    return;
  }
  if (family == AF_INET) {
    if (network_info_[index].address_family() == NetworkInfo::V4) {
      network_info_.erase(index);
      LOG(INFO) << "Removed interface " << index << " from list.";
    } else if (network_info_[index].address_family() == NetworkInfo::V4V6) {
      network_info_[index].set_address_family(NetworkInfo::V6);
    } else {
      LOG(ERROR) << "RemoveNetwork called for V4, but only V6 in map: "
                 << index;
    }
  } else if (family == AF_INET6) {
    if (network_info_[index].address_family() == NetworkInfo::V6) {
      network_info_.erase(index);
      LOG(INFO) << "Removed interface " << index << " from list.";
    } else if (network_info_[index].address_family() == NetworkInfo::V4V6) {
      network_info_[index].set_address_family(NetworkInfo::V4);
    } else {
      LOG(ERROR) << "RemoveNetwork called for V6, but only V4 in map: "
                 << index;
    }
  }
}

void NetworkMonitor::HandleParameterChanged(MIB_IPINTERFACE_ROW* row) {
  auto index = row->InterfaceIndex;

  // Update the interfaces map with any changes.
  if (network_info_.find(index) != network_info_.end()) {
    // Update the address family if changed.
    if (network_info_[index].address_family() == NetworkInfo::V4) {
      if (row->Family == AF_INET6 && row->Connected) {
        network_info_[index].set_address_family(NetworkInfo::V4V6);
        LOG(INFO) << "Interface " << index << " is now V4V6 from V4.";
      }
    } else if (network_info_[index].address_family() == NetworkInfo::V6) {
      if (row->Family == AF_INET && row->Connected) {
        network_info_[index].set_address_family(NetworkInfo::V4V6);
        LOG(INFO) << "Interface " << index << " is now V4V6 from V6.";
      }
    }
  }

  if (row->Connected) {
    // If we didn't have the row, and it's now connected, add it.
    LOG(INFO) << "Interface " << index << " is now connected.";
    if (network_info_.find(index) == network_info_.end()) {
      AddNetwork(row);
    }
  } else {
    // If the row is not connected, and it's in the map, remove the row.
    LOG(INFO) << "Interface " << index << " is disconnected.";
    if (network_info_.find(index) != network_info_.end()) {
      RemoveNetwork(index, row->Family);
    }
  }
}

void NetworkMonitor::SelectBestNetwork() {
  // Pick the best network.
  std::optional<uint64_t> best_index = std::nullopt;
  for (const auto& [id, network] : network_info_) {
    if (best_index == std::nullopt) {
      best_index = id;
      continue;
    }
    if (IsBetterNetwork(network, network_info_[*best_index])) {
      best_index = id;
    }
  }

  if (best_index == current_index_ && initial_network_set_) {
    if (best_index == std::nullopt) {
      LOG(INFO) << "Xenon: There is still no usable network.";
    } else {
      LOG(INFO) << "Xenon: The best network interface has not changed.";
    }
    return;
  }

  std::optional<NetworkInfo> best_network;
  if (best_index == std::nullopt) {
    LOG(INFO) << "Xenon: Switching to no network.";
  } else {
    best_network = network_info_[*best_index];
    LOG(INFO) << "Xenon: Switching to new best network "
              << xenon::GetNetworkInfoDebugString(*best_network);
  }

  current_index_ = best_index;

  auto notification = notification_;
  if (notification != nullptr) {
    notification_looper_->Post([notification, best_network] {
      notification->BestNetworkChanged(best_network);
    });
  }

  if (!initial_network_set_) {
    initial_network_set_ = true;
  }
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
