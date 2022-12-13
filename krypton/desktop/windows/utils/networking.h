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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_NETWORKING_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_NETWORKING_H_

// Include order matters for Windows.
// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <ifdef.h>
// clang-format on

#include <memory>

#include "privacy/net/krypton/desktop/windows/rio_socket.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

// Adds a private address to a network interface, specified by LUID.
absl::Status SetAdapterLocalAddress(
    NET_LUID luid, ::privacy::krypton::utils::IPRange private_addr_range);

// Removes an address from a network interface.
absl::Status RemoveAdapterLocalAddress(NET_LUID luid, int family);

// Adds 0.0.0.0/0 and 0::0/0 routes to a network interface.
// All device traffic will be routed to the network interface.
absl::Status SetAdapterDefaultRoute(NET_LUID interface_luid,
                                    int interface_index);

absl::Status RemoveAdapterDefaultRoute(NET_LUID interface_luid,
                                       int interface_index);

// Creates a VPN network socket. src_addr is a non-Wintun interface's private
// address, dest_addr is the Copper endpoint, and interface_index specifies a
// non-VPN interface so that socket traffic bypasses the VPN.
absl::StatusOr<std::unique_ptr<Socket>> CreateNetworkSocket(
    ::privacy::krypton::Endpoint src_addr,
    ::privacy::krypton::Endpoint dest_addr, int interface_index);

// Creates a Registered I/O network socket. src_addr is a non-Wintun interface's
// private address, dest_addr is the Copper endpoint, and interface_index
// specifies a non-VPN interface so that socket traffic bypasses the VPN.
absl::StatusOr<std::unique_ptr<RioSocket>> CreateRioNetworkSocket(
    ::privacy::krypton::Endpoint src_addr,
    ::privacy::krypton::Endpoint dest_addr, int interface_index);

// Gets the network interface index associated with a NET_LUID value.
absl::StatusOr<int> GetInterfaceIndexFromLuid(NET_LUID luid);

// Gets the index of the interface with the best route to the specified address.
// This should be called before changing the routing table and especially before
// calling SetAdapterDefaultRoute.
absl::StatusOr<int> GetBestInterfaceIndex(::privacy::krypton::Endpoint dest);

// Gets the IPv4 address of the specified interface.
absl::StatusOr<::privacy::krypton::Endpoint>
GetInterfaceIPv4Address(int if_index);

// Gets the IPv6 address of the specified interface.
absl::StatusOr<::privacy::krypton::Endpoint> GetInterfaceIPv6Address(
    int if_index);

// Sets the MTU of the specified interface.
absl::Status SetInterfaceMtu(NET_LUID luid, int mtu);

// Checks whether a network interface can connect to a remote address.
absl::Status InterfaceConnectivityCheck(int interface_index, int family);

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_UTILS_NETWORKING_H_
