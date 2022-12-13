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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_XENON_NETWORK_DEBUG_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_XENON_NETWORK_DEBUG_H_

// For winsock, the order of the includes matters.
// clang-format off
#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <winsock2.h>
#include <iphlpapi.h>
// clang-format on

#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace xenon {

std::string GetInterfaceDebugString(const MIB_IF_ROW2& row);
std::string GetIpInterfaceDebugString(const MIB_IPINTERFACE_ROW& row);
std::string GetNetworkInfoDebugString(const NetworkInfo& network_info);
std::string GetNetworkTypeDebugString(NetworkType type);

}  // namespace xenon
}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_XENON_NETWORK_DEBUG_H_
