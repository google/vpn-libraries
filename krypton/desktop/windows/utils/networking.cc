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

#include "privacy/net/krypton/desktop/windows/utils/networking.h"

// For winsock, the order of the includes matters.
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <netioapi.h>
#include <ip2string.h>
#include <guiddef.h>
// clang-format on

#include <memory>
#include <string>

#include "privacy/net/krypton/desktop/windows/rio_socket.h"
#include "privacy/net/krypton/desktop/windows/socket.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {

using ::privacy::krypton::Endpoint;
using ::privacy::krypton::utils::IPRange;

absl::Status SetAdapterLocalAddress(NET_LUID luid, IPRange private_addr_range) {
  LOG(INFO) << "Calling SetAdapterLocalAddress with IPRange "
      << private_addr_range.address();
  // Remove any other addresses on the adapter before adding a new one.
  PPN_RETURN_IF_ERROR(
      RemoveAdapterLocalAddress(luid, private_addr_range.family()));

  // AddressRow must be set to the user_private_ip from AddEgressResponse.
  MIB_UNICASTIPADDRESS_ROW AddressRow;
  InitializeUnicastIpAddressEntry(&AddressRow);
  AddressRow.InterfaceLuid = luid;

  if (private_addr_range.family() == AF_INET) {
    AddressRow.Address.si_family = AF_INET;
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    inet_pton(AF_INET, private_addr_range.address().c_str(),
              &AddressRow.Address.Ipv4.sin_addr.S_un.S_addr);
    AddressRow.OnLinkPrefixLength = *private_addr_range.prefix();
    AddressRow.DadState = IpDadStatePreferred;

  } else if (private_addr_range.family() == AF_INET6) {
    AddressRow.Address.si_family = AF_INET6;
    AddressRow.Address.Ipv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, private_addr_range.address().c_str(),
              &AddressRow.Address.Ipv6.sin6_addr.s6_addr);
    AddressRow.OnLinkPrefixLength = *private_addr_range.prefix();
    AddressRow.DadState = IpDadStatePreferred;

  } else {
    return absl::UnimplementedError("Non-IP addr families not supported");
  }

  auto err = CreateUnicastIpAddressEntry(&AddressRow);
  if (err != NO_ERROR) {
    return GetStatusForError("CreateUnicastIpAddressEntry error", err);
  }
  return absl::OkStatus();
}

absl::Status RemoveAdapterLocalAddress(NET_LUID luid, int family) {
  LOG(INFO) << "Calling RemoveAdapterLocalAddress for family " << family;
  // Get the table of MIB_UNICASTIPADDRESS_ROWs.
  PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
  auto result = GetUnicastIpAddressTable(family, &table);
  if (result != NO_ERROR) {
    return GetStatusForError("GetUnicastIpAddressTable failed", result);
  }
  auto table_cleanup = absl::MakeCleanup([table]() { FreeMibTable(table); });

  // Find and delete the address row that's on the adapter.
  for (int i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Value == luid.Value) {
      result = DeleteUnicastIpAddressEntry(&table->Table[i]);
      if (result != NO_ERROR) {
        return GetStatusForError("DeleteUnicastIpAddressEntry failed", result);
      }
    }
  }
  return absl::OkStatus();
}

void PopulateForwardRow(MIB_IPFORWARD_ROW2 *row, NET_LUID interface_luid,
                        int interface_index, int si_family) {
  InitializeIpForwardEntry(row);

  row->InterfaceLuid = interface_luid;
  row->InterfaceIndex = interface_index;
  row->DestinationPrefix.Prefix.si_family = si_family;
  row->DestinationPrefix.PrefixLength = 0;
  row->Protocol = MIB_IPPROTO_NETMGMT;
  row->Metric = 10;
}

absl::Status SetAdapterDefaultRoute(NET_LUID interface_luid,
                                    int interface_index) {
  LOG(INFO) << "Calling SetAdapterDefaultRoute with index " << interface_index;

  // IPv4
  MIB_IPFORWARD_ROW2 row;
  memset(&row, 0, sizeof(row));
  PopulateForwardRow(&row, interface_luid, interface_index, AF_INET);
  auto result = CreateIpForwardEntry2(&row);
  if (result != NO_ERROR) {
    return GetStatusForError("CreateIpForwardEntry2 (IPv4) error", result);
  }

  // IPv6
  memset(&row, 0, sizeof(row));
  PopulateForwardRow(&row, interface_luid, interface_index, AF_INET6);
  result = CreateIpForwardEntry2(&row);
  if (result != NO_ERROR) {
    return GetStatusForError("CreateIpForwardEntry2 (IPv6) error", result);
  }

  return absl::OkStatus();
}

absl::Status RemoveAdapterDefaultRoute(NET_LUID interface_luid,
                                       int interface_index) {
  LOG(INFO) << "Calling RemoveAdapterDefaultRoute with index "
            << interface_index;
  MIB_IPFORWARD_ROW2 row = {};

  // IPv4
  memset(&row, 0, sizeof(row));
  PopulateForwardRow(&row, interface_luid, interface_index, AF_INET);
  auto result = DeleteIpForwardEntry2(&row);
  if (result != NO_ERROR) {
    return GetStatusForError("DeleteIpForwardEntry2 (IPv4) error", result);
  }

  // IPv6
  memset(&row, 0, sizeof(row));
  PopulateForwardRow(&row, interface_luid, interface_index, AF_INET6);
  result = DeleteIpForwardEntry2(&row);
  if (result != NO_ERROR) {
    return GetStatusForError("DeleteIpForwardEntry2 (IPv6) error", result);
  }

  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<Socket>> CreateNetworkSocket(
    Endpoint src_endpoint, Endpoint dst_endpoint, int if_index) {
  LOG(INFO) << "Calling CreateNetworkSocket with if_index " << if_index;
  LOG(INFO) << "Connecting from " << src_endpoint.ToString() << " to "
            << dst_endpoint.ToString();

  if (src_endpoint.ip_protocol() != dst_endpoint.ip_protocol()) {
    return absl::InvalidArgumentError(
        "src ip and dst ip have different protocols");
  }

  int family =
      (src_endpoint.ip_protocol() == IPProtocol::kIPv4 ? AF_INET : AF_INET6);

  int src_port = src_endpoint.port();
  int dst_port = dst_endpoint.port();

  // Create socket to remote server.
  sockaddr_storage dst_addr, src_addr;
  socklen_t dst_addr_size, src_addr_size;

  PPN_ASSIGN_OR_RETURN(auto src_range,
                       utils::IPRange::Parse(src_endpoint.address()));
  PPN_RETURN_IF_ERROR(
      src_range.GenericAddress(src_port, &src_addr, &src_addr_size));

  PPN_ASSIGN_OR_RETURN(auto dst_range,
                       utils::IPRange::Parse(dst_endpoint.address()));
  PPN_RETURN_IF_ERROR(
      dst_range.GenericAddress(dst_port, &dst_addr, &dst_addr_size));

  // Create socket.
  SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) {
    return absl::InternalError("socket failed");
  }
  auto unique_socket = std::make_unique<Socket>(s);

  // Bind socket.
  if (bind(s, reinterpret_cast<sockaddr *>(&src_addr), src_addr_size) ==
      SOCKET_ERROR) {
    return GetStatusForError("bind failed", WSAGetLastError());
  }

  if (family == AF_INET) {
    // Argument to setsockopt must be a string in network byte order.
    DWORD if_index_n = htonl(if_index);
    if (setsockopt(s, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<char *>(&if_index_n),
                   sizeof(if_index_n)) != 0) {
      return GetStatusForError("setsockopt failed for IPPROTO_IP",
                               WSAGetLastError());
    }
  } else if (family == AF_INET6) {
    // For IPv6, the equivalent value must be specified in host order. Really.
    DWORD if_index_n = if_index;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
                   reinterpret_cast<char *>(&if_index_n),
                   sizeof(if_index_n)) != 0) {
      return GetStatusForError("setsockopt failed for IPPROTO_IPV6",
                               WSAGetLastError());
    }
  }

  if (connect(s, reinterpret_cast<struct sockaddr *>(&dst_addr),
              dst_addr_size) != 0) {
    return GetStatusForError("connect failed", WSAGetLastError());
  }

  LOG(INFO) << "Created network socket.";
  return unique_socket;
}

absl::StatusOr<std::unique_ptr<RioSocket>> CreateRioNetworkSocket(
    Endpoint src_addr, Endpoint dest_addr, int interface_index) {
  auto socket = std::make_unique<RioSocket>(src_addr, interface_index);
  PPN_RETURN_IF_ERROR(socket->Open());
  PPN_RETURN_IF_ERROR(socket->Connect(dest_addr));
  return socket;
}

absl::StatusOr<int> GetInterfaceIndexFromLuid(NET_LUID luid) {
  LOG(INFO) << "Calling GetInterfaceIndexFromLuid";
  NET_IFINDEX index;
  auto result = ConvertInterfaceLuidToIndex(&luid, &index);
  if (result != NO_ERROR) {
    return GetStatusForError("GetIfIndexFromLuid", result);
  }
  LOG(INFO) << "GetInterfaceIndexFromLuid is returning index " << index;
  return index;
}

absl::StatusOr<int> GetBestInterfaceIndex(::privacy::krypton::Endpoint dest) {
  LOG(INFO) << "Calling GetBestInterfaceIndex";

  int port = dest.port();
  sockaddr_storage addr;
  socklen_t addr_size;

  PPN_ASSIGN_OR_RETURN(auto ip_range, utils::IPRange::Parse(dest.address()));
  PPN_RETURN_IF_ERROR(ip_range.GenericAddress(port, &addr, &addr_size));

  DWORD index = -1;
  auto result = GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&addr), &index);
  if (result != NO_ERROR) {
    return GetStatusForError("GetBestInterfaceEx", result);
  }
  LOG(INFO) << "GetBestInterfaceIndex is returning " << index;
  return index;
}

absl::StatusOr<::privacy::krypton::Endpoint> GetInterfaceIPv4Address(
    int if_index) {
  LOG(INFO) << "Calling GetInterfaceIPv4Address with if_index " << if_index;
  PMIB_IPADDRTABLE table = nullptr;
  ULONG size = 0;

  // Call once to get the correct buffer size for the table.
  auto result = GetIpAddrTable(table, &size, false);
  if (result != ERROR_INSUFFICIENT_BUFFER) {
    return GetStatusForError("GetIpAddrTable", result);
  }
  table = reinterpret_cast<MIB_IPADDRTABLE*>(malloc(size));
  auto table_closer = absl::MakeCleanup([table] {
    free(reinterpret_cast<void*>(table));
  });

  // The second call will get the actual data.
  result = GetIpAddrTable(table, &size, FALSE);
  if (result != ERROR_SUCCESS) {
    return GetStatusForError("GetIpAddrTable", result);
  }

  // Find the address for if_index.
  for (int i = 0; i < table->dwNumEntries; i++) {
    if (table->table[i].dwIndex == if_index) {
      // return an Endpoint
      IN_ADDR if_addr;
      if_addr.S_un.S_addr = static_cast<u_long>(table->table[i].dwAddr);
      auto addr_string = absl::StrCat(inet_ntoa(if_addr), ":0");
      PPN_ASSIGN_OR_RETURN(auto endpoint, GetEndpointFromHostPort(addr_string));
      return endpoint;
    }
  }
  return absl::NotFoundError("Could not find interface with specified index");
}

absl::StatusOr<::privacy::krypton::Endpoint> GetInterfaceIPv6Address(
    int if_index) {
  LOG(INFO) << "Calling GetInterfaceIPv6Address with if_index " << if_index;

  // Following the example code at:
  // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
  IP_ADAPTER_ADDRESSES *addresses = nullptr;
  auto free_addresses = absl::MakeCleanup([&addresses]() {
    if (addresses != nullptr) {
      free(addresses);
    }
  });
  // From the docs, try first with a 15kb array.
  unsigned long addresses_size = 15000;  // NOLINT
  int tries = 3;
  while (true) {
    tries--;
    if (tries <= 0) {
      return absl::InternalError("Unable to GetAdaptersAddresses.");
    }

    addresses =
        reinterpret_cast<IP_ADAPTER_ADDRESSES *>(malloc(addresses_size));
    if (addresses == nullptr) {
      return absl::InternalError("Unable to allocate IP_ADAPTER_ADDRESSES");
    }
    int ret =
        GetAdaptersAddresses(AF_INET6, 0, nullptr, addresses, &addresses_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      // The call updated addresses_size, so just try again with the new size.
      free(addresses);
      addresses = nullptr;
      continue;
    }
    if (ret != ERROR_SUCCESS) {
      return GetStatusForError("Unable to GetAdaptersAddresses", ret);
    }
    break;
  }

  // Find the adapter with that interface.
  for (IP_ADAPTER_ADDRESSES *address = addresses; address != nullptr;
       address = address->Next) {
    if (address->Ipv6IfIndex != if_index) {
      continue;
    }
    // Find the IPv6 address for UDP.
    for (IP_ADAPTER_UNICAST_ADDRESS *unicast = address->FirstUnicastAddress;
         unicast != nullptr; unicast = unicast->Next) {
      if (unicast->Address.lpSockaddr->sa_family != AF_INET6) {
        continue;
      }
      if (unicast->Address.iSockaddrLength < sizeof(sockaddr_in6)) {
        return absl::InternalError("IPv6 sockaddr has incorrect length");
      }

      // Convert the IP address into a host-port string.
      sockaddr_in6 *addr =
          reinterpret_cast<sockaddr_in6 *>(unicast->Address.lpSockaddr);
      if (addr == nullptr) {
        return absl::InternalError("reinterpret_cast to sockaddr_in6 failed");
      }
      char out[INET6_ADDRSTRLEN];
      if (inet_ntop(AF_INET6, &(addr->sin6_addr), out, sizeof(out)) ==
          nullptr) {
        return GetStatusForError("inet_ntop failed", errno);
      }
      auto addr_str = absl::StrCat("[", out, "]:0");
      return GetEndpointFromHostPort(addr_str);
    }
  }
  LOG(FATAL) << "Unable to find IPv6 address of interface: " << if_index;

  return absl::InternalError(
      absl::StrCat("Unable to find IPv6 address of interface: ", if_index));
}

absl::Status SetInterfaceMtu(NET_LUID luid, int mtu) {
  LOG(INFO) << "Calling SetInterfaceMtu with MTU " << mtu;
  MIB_IPINTERFACE_ROW interface_row;
  memset(&interface_row, 0, sizeof(interface_row));

  interface_row.InterfaceLuid = luid;
  interface_row.Family = AF_INET;
  int result = GetIpInterfaceEntry(&interface_row);
  if (result != NO_ERROR) {
    return GetStatusForError("GetIpInterfaceEntry", result);
  }

  interface_row.InterfaceLuid = luid;
  interface_row.Family = AF_INET;
  interface_row.NlMtu = mtu;
  interface_row.SitePrefixLength = 0;
  result = SetIpInterfaceEntry(&interface_row);
  if (result != NO_ERROR) {
    return GetStatusForError("SetIpInterfaceEntry", result);
  }
  return absl::OkStatus();
}

absl::Status InterfaceConnectivityCheck(int interface_index, int family) {
  LOG(INFO) << "Checking connectivity on interface " << interface_index
            << " for family " << family;
  // Create a socket and try to connect to a specific URL.
  SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    return absl::InternalError("socket failed");
  }
  auto socket_cleanup = absl::MakeCleanup([s] { closesocket(s); });

  // Force socket to use the specified interface.
  if (family == AF_INET) {
    // Argument to setsockopt must be a string in network byte order.
    DWORD interface_index_n = htonl(interface_index);
    if (setsockopt(s, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<char *>(&interface_index_n),
                   sizeof(interface_index_n)) != 0) {
      return GetStatusForError("setsockopt failed for IPPROTO_IP",
                               WSAGetLastError());
    }
  } else if (family == AF_INET6) {
    // For IPv6, the equivalent value must be specified in host order. Really.
    DWORD interface_index_n = interface_index;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
                   reinterpret_cast<char *>(&interface_index_n),
                   sizeof(interface_index_n)) != 0) {
      return GetStatusForError("setsockopt failed for IPPROTO_IPV6",
                               WSAGetLastError());
    }
  } else {
    LOG(ERROR) << "Family is not AF_INET or AF_INET6: " << family;
    return absl::InvalidArgumentError("Family is not AF_INET or AF_INET6");
  }

  // Try connecting to a URL as a connectivity check.
  TIMEVAL timeout;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  auto result = WSAConnectByNameA(s, "www.google.com", "https", NULL, NULL,
                                  NULL, NULL, &timeout, NULL);
  if (!result) {
    auto status =
        GetStatusForError("WSAConnectByNameA failed", WSAGetLastError());
    LOG(ERROR) << "Connectivity check failed for interface "
               << interface_index << ": " << status;
    return status;
  }
  LOG(INFO) << "Connectivity check succeeded on interface " << interface_index
            << " for family " << family;
  return absl::OkStatus();
}

absl::Status AddDnsServersToInterface(NET_LUID luid, ADDRESS_FAMILY family) {
  const wchar_t *v4_name_servers = L"8.8.4.4, 8.8.8.8";
  const wchar_t *v6_name_servers =
      L"2001:4860:4860::8888, 2001:4860:4860::8844";
  GUID guid = {};
  DWORD result = ConvertInterfaceLuidToGuid(&luid, &guid);
  if (result != NO_ERROR) {
    return GetStatusForError("ConvertInterfaceLuidToGuid", result);
  }

  DNS_INTERFACE_SETTINGS settings = {};
  settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
  if (family == AF_INET) {
    settings.Flags = DNS_SETTING_NAMESERVER;
    settings.NameServer = const_cast<wchar_t *>(v4_name_servers);
    result = SetInterfaceDnsSettings(guid, &settings);
    if (result != NO_ERROR) {
      return GetStatusForError("SetInterfaceDnsSettings", result);
    }
  } else if (family == AF_INET6) {
    settings.Flags = DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6;
    settings.NameServer = const_cast<wchar_t *>(v6_name_servers);
    result = SetInterfaceDnsSettings(guid, &settings);
    if (result != NO_ERROR) {
      return GetStatusForError("SetInterfaceDnsSettings", result);
    }
  }
  return absl::OkStatus();
}

absl::Status AddDnsToAllInterfaces() {
  PMIB_IPINTERFACE_TABLE table = nullptr;
  DWORD result = GetIpInterfaceTable(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    return GetStatusForError("GetIpInterfaceTable", result);
  }
  auto table_cleanup = absl::MakeCleanup([table]() { FreeMibTable(table); });

  for (int i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].Family == AF_INET) {
      PPN_RETURN_IF_ERROR(
          AddDnsServersToInterface(table->Table[i].InterfaceLuid, AF_INET));
    } else if (table->Table[i].Family == AF_INET6) {
      PPN_RETURN_IF_ERROR(
          AddDnsServersToInterface(table->Table[i].InterfaceLuid, AF_INET6));
    }
  }
  return absl::OkStatus();
}

}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
