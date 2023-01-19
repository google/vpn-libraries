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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_H_

#include <windows.h>

#include <cstdint>
#include <string>

#include "privacy/net/krypton/desktop/windows/wintun_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/common/proto/ppn_status.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/wintun/api/wintun.h"

namespace privacy {
namespace krypton {
namespace windows {

class Wintun : public WintunInterface {
 public:
  Wintun() {}
  ~Wintun() override;

  // Disllow copy, move, and assign.
  Wintun(const Wintun& other) = delete;
  Wintun(Wintun&& other) = delete;
  Wintun& operator=(const Wintun& other) = delete;
  Wintun& operator=(Wintun&& other) = delete;

  absl::Status Initialize();

  absl::Status CreateAdapter(absl::string_view name,
                             absl::string_view tunnel_type) override;

  absl::Status CloseAdapter() override;

  // If the function succeeds, the return value is the version number.
  // If the function fails, the return value is zero, including when the driver
  // is not loaded.
  uint32_t GetRunningDriverVersion() override;

  void SetAbslLogger() override;

  absl::StatusOr<NET_LUID> GetAdapterLUID();

  absl::Status StartSession() override;

  absl::Status EndSession() override;

  // Event HANDLE is valid for the session. Caller should NOT call CloseHandle,
  // HANDLE is managed by the session. HANDLE is no longer valid after
  // EndSession is called.
  HANDLE GetWaitReadEvent();

  // Returns a Krypton Packet. Wintun owns the memory, SendPacket will release
  // the internal buffer.
  absl::StatusOr<Packet> AllocateSendPacket(uint32_t packet_size) override;

  absl::Status AllocateAndSendPacket(
      uint8_t* buffer, size_t actual_output_size);

  // Packet must be allocated using Wintun::AllocateSendPacket. After sending,
  // Wintun will free the packet buffer. Amount of data sent depends on the
  // packet_size passed to AllocateSendPacket and the size indicated in the
  // packet header.
  absl::Status SendPacket(Packet packet) override;

  absl::StatusOr<Packet> ReceivePacket() override;

  absl::Status ReleaseReceivePacket(Packet packet) override;

  // Returns absl::OkStatus if Wintun is successfully initialized.
  // Returns a permanent error status if Wintun is not initialized.
  absl::Status IsWintunInitialized();

 private:
  absl::Status EnsureLibraryExists();
  absl::Status EnsureAdapterExists();
  absl::Status EnsureSessionExists();

  HMODULE wintun_ = nullptr;
  // We expect to use only one adapter and session at a time.
  WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
  WINTUN_SESSION_HANDLE session_ = nullptr;

  // These are functions provided by wintun.dll. They are named to match the
  // official function names exported by the library, rather than be mangled to
  // match the normal style for private data members.
  WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
  WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
  WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
  WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
  WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
  WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
  WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
  WINTUN_START_SESSION_FUNC *WintunStartSession;
  WINTUN_END_SESSION_FUNC *WintunEndSession;
  WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
  WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
  WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
  WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
  WINTUN_SEND_PACKET_FUNC *WintunSendPacket;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_WINTUN_H_
