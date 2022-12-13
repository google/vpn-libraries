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

#include "privacy/net/krypton/desktop/windows/xenon/network_debug.h"

#include <combaseapi.h>

#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/proto/network_type.proto.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace xenon {

const char* GetRowTypeDebugString(IFTYPE type) {
  // There is a huge list of possible interface types, and we don't care about
  // most of the distinctions, but there are a handful that are common and
  // notable.
  // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-interface-types
  switch (type) {
    case IF_TYPE_ETHERNET_CSMACD:
      return "Ethernet CSMA/CD";
    case IF_TYPE_SOFTWARE_LOOPBACK:
      return "Software Loopback";
    case IF_TYPE_TUNNEL:
      return "Tunnel";
    case IF_TYPE_IEEE80211:
      return "WiFi 802.11";
    case IF_TYPE_PROP_VIRTUAL:
      return "Proprietary Virtual";
    default:
      return "Other";
  }
}

const char* GetTunnelTypeDebugString(TUNNEL_TYPE type) {
  switch (type) {
    case TUNNEL_TYPE_NONE:
      return "None";
    case TUNNEL_TYPE_OTHER:
      return "Other";
    case TUNNEL_TYPE_DIRECT:
      return "Direct";
    case TUNNEL_TYPE_6TO4:
      return "6to4";
    case TUNNEL_TYPE_ISATAP:
      return "ISATAP";
    case TUNNEL_TYPE_TEREDO:
      return "Teredo";
    case TUNNEL_TYPE_IPHTTPS:
      return "IP-HTTPS";
    default:
      return "Unknown";
  }
}

const char* GetOperStatusDebugString(IF_OPER_STATUS status) {
  switch (status) {
    case IfOperStatusUp:
      return "Up";
    case IfOperStatusDown:
      return "Down";
    case IfOperStatusTesting:
      return "Testing";
    case IfOperStatusUnknown:
      return "Unknown";
    case IfOperStatusDormant:
      return "Dormant";
    case IfOperStatusNotPresent:
      return "Not Present";
    case IfOperStatusLowerLayerDown:
      return "Lower Layer Down";
    default:
      return "Other";
  }
}

const char* GetMediaConnectStateDebugString(NET_IF_MEDIA_CONNECT_STATE state) {
  switch (state) {
    case MediaConnectStateUnknown:
      return "Unknown";
    case MediaConnectStateConnected:
      return "Connected";
    case MediaConnectStateDisconnected:
      return "Disconnected";
    default:
      return "Other";
  }
}

const char* GetAccessTypeDebugString(NET_IF_ACCESS_TYPE type) {
  switch (type) {
    case NET_IF_ACCESS_LOOPBACK:
      return "Loopback";
    case NET_IF_ACCESS_BROADCAST:
      return "Broadcast";
    case NET_IF_ACCESS_POINT_TO_POINT:
      return "Point-to-point";
    case NET_IF_ACCESS_POINT_TO_MULTI_POINT:
      return "Point-to-multi-point";
    default:
      return "Other";
  }
}

const char* GetDirectionTypeDebugString(NET_IF_DIRECTION_TYPE type) {
  switch (type) {
    case NET_IF_DIRECTION_SENDRECEIVE:
      return "Send/Receive";
    case NET_IF_DIRECTION_SENDONLY:
      return "Send";
    case NET_IF_DIRECTION_RECEIVEONLY:
      return "Receive";
    default:
      return "Other";
  }
}

std::string GetInterfaceDebugString(const MIB_IF_ROW2& row) {
  std::string output = "Interface {\n";
  absl::StrAppend(&output, "  Index: ", row.InterfaceIndex);

  wchar_t guid[40] = L"";
  if (StringFromGUID2(row.InterfaceGuid, guid, 40) == 0) {
    absl::StrAppend(&output, "\n  Guid: <StringFromGUID2 failed");
  } else {
    absl::StrAppend(&output, "\n  Guid: ", utils::WcharToString(guid));
  }

  absl::StrAppend(&output,
                  "\n  Interface name: ", utils::WcharToString(row.Alias));
  absl::StrAppend(&output, "\n  Interface description: ",
                  utils::WcharToString(row.Description));

  absl::StrAppendFormat(&output, "\n  Type: %s (%d)",
                        GetRowTypeDebugString(row.Type), row.Type);
  absl::StrAppendFormat(&output, "\n  TunnelType: %s (%d)",
                        GetTunnelTypeDebugString(row.TunnelType),
                        row.TunnelType);
  absl::StrAppendFormat(&output, "\n  OperStatus: %s (%d)",
                        GetOperStatusDebugString(row.OperStatus),
                        row.OperStatus);
  absl::StrAppendFormat(&output, "\n  MediaConnectState: %s (%d)",
                        GetMediaConnectStateDebugString(row.MediaConnectState),
                        row.MediaConnectState);
  absl::StrAppendFormat(&output, "\n  AccessType: %s (%d)",
                        GetAccessTypeDebugString(row.AccessType),
                        row.AccessType);
  absl::StrAppendFormat(&output, "\n  DirectionType: %s (%d)",
                        GetDirectionTypeDebugString(row.DirectionType),
                        row.DirectionType);

  absl::StrAppendFormat(&output, "\n  Mtu: %d", row.Mtu);

  absl::StrAppend(&output, "\n}");

  return output;
}

const char* GetFamilyDebugString(ADDRESS_FAMILY family) {
  switch (family) {
    case AF_UNSPEC:
      return "Unspecified";
    case AF_INET:
      return "IPv4";
    case AF_INET6:
      return "IPv6";
    default:
      return "Other";
  }
}

std::string GetIpInterfaceDebugString(const MIB_IPINTERFACE_ROW& row) {
  std::string output = "IpInterface {";
  absl::StrAppendFormat(&output, "\n  Family: %s (%d)",
                        GetFamilyDebugString(row.Family), row.Family);
  absl::StrAppendFormat(&output, "\n  Index: %d", row.InterfaceIndex);
  absl::StrAppendFormat(&output, "\n  Connected: %s",
                        (row.Connected ? "True" : "False"));
  absl::StrAppend(&output, "\n}");
  return output;
}

std::string GetAddressFamilyDebugString(NetworkInfo::AddressFamily family) {
  switch (family) {
    case NetworkInfo::V4:
      return "V4";
    case NetworkInfo::V6:
      return "V6";
    case NetworkInfo::V4V6:
      return "V4V6";
    default:
      return "UNKNOWN";
  }
}

std::string GetNetworkTypeDebugString(NetworkType type) {
  switch (type) {
    case ETHERNET:
      return "ETHERNET";
    case WIFI:
      return "WIFI";
    case CELLULAR:
      return "CELLULAR";
    default:
      return "UNKNOWN";
  }
}

std::string GetNetworkInfoDebugString(const NetworkInfo& network_info) {
  std::string output = "NetworkInfo {";
  absl::StrAppendFormat(&output, "\n  id: (%ld)", network_info.network_id());
  absl::StrAppendFormat(&output, "\n  type: %s",
                        GetNetworkTypeDebugString(network_info.network_type()));
  absl::StrAppendFormat(
      &output, "\n  family: %s",
      GetAddressFamilyDebugString(network_info.address_family()));
  absl::StrAppend(&output, "\n}");
  return output;
}

}  // namespace xenon
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
