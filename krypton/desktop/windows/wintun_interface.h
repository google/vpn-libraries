/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_INTERFACE_H_

#include <windows.h>
#include <ifdef.h>

#include <cstdint>
#include <string>

#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {

class WintunInterface {
 public:
  virtual ~WintunInterface() = default;

  virtual absl::Status CreateAdapter(absl::string_view name,
                                     absl::string_view tunnel_type) = 0;

  virtual absl::Status CloseAdapter() = 0;

  // If the function succeeds, the return value is the version number.
  // If the function fails, the return value is zero, including when the driver
  // is not loaded.
  virtual uint32_t GetRunningDriverVersion() = 0;

  virtual void SetAbslLogger() = 0;

  virtual absl::StatusOr<NET_LUID> GetAdapterLUID() = 0;

  virtual absl::Status StartSession() = 0;

  virtual absl::Status EndSession() = 0;

  // Event HANDLE is valid for the session. Caller should NOT call CloseHandle,
  // HANDLE is managed by the session. HANDLE is no longer valid after
  // EndSession is called.
  virtual HANDLE GetWaitReadEvent() = 0;

  // Returns a Krypton Packet. Wintun owns the memory, SendPacket will release
  // the internal buffer.
  virtual absl::StatusOr<Packet> AllocateSendPacket(uint32_t packet_size) = 0;

  // Packet must be allocated using Wintun::AllocateSendPacket. After sending,
  // Wintun will free the packet buffer. Amount of data sent depends on the
  // packet_size passed to AllocateSendPacket and the size indicated in the
  // packet header.
  virtual absl::Status SendPacket(Packet packet) = 0;

  virtual absl::StatusOr<Packet> ReceivePacket() = 0;

  virtual absl::Status ReleaseReceivePacket(Packet packet) = 0;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_INTERFACE_H_
