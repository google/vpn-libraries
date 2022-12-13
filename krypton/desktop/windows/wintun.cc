// TODO  : Refactor this file to reflect that it is using GOOGTUN.

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

#include "privacy/net/krypton/desktop/windows/wintun.h"

#include <cstdint>
#include <iostream>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/datapath/utils/utils.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/wintun/api/wintun.h"
#include "privacy/net/krypton/utils/status.h"

namespace privacy {
namespace krypton {
namespace windows {

static void AbslLogger(WINTUN_LOGGER_LEVEL level, DWORD64 timestamp,
                       const WCHAR* message);

Wintun::~Wintun() {
  LOG(INFO) << "Destroying Wintun";
  if (wintun_ != nullptr) {
    FreeLibrary(wintun_);
    wintun_ = nullptr;
  }
}

absl::Status Wintun::Initialize() {
  if (wintun_ != nullptr) {
    return absl::AlreadyExistsError("Wintun has already been initialized");
  }
  // Googtun DLL is only searched for in the directory where the application is
  // present.
  wintun_ = LoadLibraryEx("googtun.dll", nullptr,
                          LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
  if (wintun_ == nullptr) {
    return utils::GetStatusForError("unable to initialize wintun",
                                    GetLastError());
  }

  // A small macro to make loading the function pointers from the DLL easier.
#define LOAD_LIBRARY_FUNCTION(name)                        \
  do {                                                     \
    *(FARPROC*)&name = GetProcAddress(wintun_, #name);     \
    if (name == nullptr) {                                 \
      return absl::InternalError("Unable to load " #name); \
    }                                                      \
  } while (0)

  LOAD_LIBRARY_FUNCTION(WintunCreateAdapter);
  LOAD_LIBRARY_FUNCTION(WintunCloseAdapter);
  LOAD_LIBRARY_FUNCTION(WintunOpenAdapter);
  LOAD_LIBRARY_FUNCTION(WintunGetAdapterLUID);
  LOAD_LIBRARY_FUNCTION(WintunGetRunningDriverVersion);
  LOAD_LIBRARY_FUNCTION(WintunDeleteDriver);
  LOAD_LIBRARY_FUNCTION(WintunSetLogger);
  LOAD_LIBRARY_FUNCTION(WintunStartSession);
  LOAD_LIBRARY_FUNCTION(WintunEndSession);
  LOAD_LIBRARY_FUNCTION(WintunGetReadWaitEvent);
  LOAD_LIBRARY_FUNCTION(WintunReceivePacket);
  LOAD_LIBRARY_FUNCTION(WintunReleaseReceivePacket);
  LOAD_LIBRARY_FUNCTION(WintunAllocateSendPacket);
  LOAD_LIBRARY_FUNCTION(WintunSendPacket);

#undef LOAD_LIBRARY_FUNCTION

  // TODO: Do any other Wintun setup here.

  return absl::OkStatus();
}

absl::Status Wintun::CreateAdapter(absl::string_view name,
                                   absl::string_view tunnel_type) {
  LOG(INFO) << "[Wintun] Calling Wintun::CreateAdapter";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  if (adapter_ != nullptr) {
    LOG(ERROR) << "[Wintun] Adapter already exists";
    return absl::InternalError("Adapter already exists");
  }
  // Convert string_view to wchar_t for WintunCreateAdapter.
  std::wstring wide_name = utils::CharToWstring(name);
  std::wstring wide_tunnel_type = utils::CharToWstring(tunnel_type);
  adapter_ =
      WintunCreateAdapter(wide_name.c_str(), wide_tunnel_type.c_str(), nullptr);
  if (adapter_ == NULL) {
    LOG(ERROR) << "[Wintun] WintunCreateAdapter failed";
    return utils::GetStatusForError("unable to create adapter", GetLastError());
  }
  LOG(INFO) << "[Wintun] Adapter created successfully";
  return absl::OkStatus();
}

absl::Status Wintun::CloseAdapter() {
  LOG(INFO) << "[Wintun] Calling Wintun::CloseAdapter";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureAdapterExists());

  WintunCloseAdapter(adapter_);
  auto error = GetLastError();
  if (error != ERROR_SUCCESS) {
    LOG(ERROR) << "[Wintun] Failed to remove adapter when closing";
    return utils::GetStatusForError("Unable to close adapter", error);
  }

  adapter_ = nullptr;
  LOG(INFO) << "[Wintun] Adapter closed successfully";
  return absl::OkStatus();
}

uint32_t Wintun::GetRunningDriverVersion() {
  LOG(INFO) << "[Wintun] Calling Wintun::GetRunningDriverVersion";
  PPN_LOG_IF_ERROR(EnsureLibraryExists());
  return (uint32_t)WintunGetRunningDriverVersion();
}

void Wintun::SetAbslLogger() {
  PPN_LOG_IF_ERROR(EnsureLibraryExists());
  WintunSetLogger(AbslLogger);
}

absl::StatusOr<NET_LUID> Wintun::GetAdapterLUID() {
  LOG(INFO) << "[Wintun] Calling Wintun::GetAdapterLUID";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureAdapterExists());

  NET_LUID luid;
  WintunGetAdapterLUID(adapter_, &luid);
  return luid;
}

absl::Status Wintun::StartSession() {
  LOG(INFO) << "[Wintun] Calling Wintun::StartSession";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureAdapterExists());

  session_ = WintunStartSession(adapter_, WINTUN_MAX_RING_CAPACITY);
  if (!session_) {
    return utils::GetStatusForError("unable to start session", GetLastError());
  }
  LOG(INFO) << "[Wintun] Started Wintun session";
  return absl::OkStatus();
}

absl::Status Wintun::EndSession() {
  LOG(INFO) << "[Wintun] Calling Wintun::EndSession";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  WintunEndSession(session_);
  session_ = nullptr;
  LOG(INFO) << "[Wintun] Ended Wintun session";
  return absl::OkStatus();
}

HANDLE Wintun::GetWaitReadEvent() {
  LOG(INFO) << "[Wintun] Calling Wintun::GetWaitReadEvent";
  PPN_LOG_IF_ERROR(EnsureLibraryExists());
  PPN_LOG_IF_ERROR(EnsureSessionExists());
  return WintunGetReadWaitEvent(session_);
}

absl::StatusOr<Packet> Wintun::AllocateSendPacket(uint32_t packet_size) {
  LOG(INFO) << "[Wintun] Calling Wintun::AllocateSendPacket";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  if (packet_size > WINTUN_MAX_IP_PACKET_SIZE || packet_size < 0) {
    return absl::InvalidArgumentError("Invalid packet size");
  }
  auto bytes =
      WintunAllocateSendPacket(session_, static_cast<DWORD>(packet_size));
  if (bytes == NULL) {
    return utils::GetStatusForError("unable to allocate send packet",
                                    GetLastError());
  }
  // Packet takes a cleanup function that's called when Krypton finishes with it
  // but we don't need it for Wintun, as WintunSendPacket must be used to free
  // the allocated memory.
  // We pass an empty block to the Packet constructor and expect a matching
  // WintunSendPacket call later.
  // TODO: automatically cleanup this memory
  return Packet(const_cast<const char*>(reinterpret_cast<char*>(bytes)),
                packet_size, krypton::IPProtocol::kUnknown, [] {});
}

absl::Status Wintun::AllocateAndSendPacket(uint8_t* buffer,
                                           size_t actual_output_size) {
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  if (actual_output_size > WINTUN_MAX_IP_PACKET_SIZE ||
      actual_output_size < 0) {
    LOG(FATAL) << "Invalid packet size";
  }

  auto bytes = WintunAllocateSendPacket(session_,
                                        static_cast<DWORD>(actual_output_size));
  if (bytes == NULL) {
    LOG(FATAL) << "unable to allocate send packet" << GetLastError();
  }
  memcpy(bytes, buffer, actual_output_size);
  WintunSendPacket(session_, bytes);
  return absl::OkStatus();
}

absl::Status Wintun::SendPacket(Packet packet) {
  LOG(INFO) << "[Wintun] Calling Wintun::SendPacket";
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  auto new_pkt = reinterpret_cast<const BYTE*>(packet.data().data());
  if (new_pkt == nullptr) {
    return absl::InternalError("Reinterpret cast returned nullptr");
  }
  WintunSendPacket(session_, new_pkt);

  return absl::OkStatus();
}

absl::StatusOr<Packet> Wintun::ReceivePacket() {
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  uint32_t packet_size;
  auto bytes =
      WintunReceivePacket(session_, reinterpret_cast<DWORD*>(&packet_size));
  if (bytes == NULL) {
    return utils::GetStatusForError("unable to receive packet", GetLastError());
  }
  uint8_t version = bytes[0] >> 4;
  IPProtocol protocol;
  if (version == 4) {
    protocol = IPProtocol::kIPv4;
  } else if (version == 6) {
    protocol = IPProtocol::kIPv6;
  } else {
    protocol = IPProtocol::kUnknown;
  }
  // Packet does not have a cleanup function. We expect the caller to use
  // Wintun::ReleaseReceivePacket to manually release the allocated buffer.
  // TODO: automatically cleanup this memory
  return Packet(reinterpret_cast<const char*>(bytes), packet_size, protocol,
                [] {});
}

absl::Status Wintun::ReleaseReceivePacket(Packet packet) {
  PPN_RETURN_IF_ERROR(EnsureLibraryExists());
  PPN_RETURN_IF_ERROR(EnsureSessionExists());

  WintunReleaseReceivePacket(
      session_, reinterpret_cast<const BYTE*>(packet.data().data()));
  return absl::OkStatus();
}

static void AbslLogger(WINTUN_LOGGER_LEVEL level, DWORD64 timestamp,
                       const WCHAR* message) {
  auto log_line = utils::WcharToString(message);
  switch (level) {
    case WINTUN_LOG_INFO: {
      LOG(INFO) << "[Driver] " << log_line;
      break;
    }
    case WINTUN_LOG_WARN: {
      LOG(WARNING) << "[Driver] " << log_line;
      break;
    }
    case WINTUN_LOG_ERR: {
      LOG(ERROR) << "[Driver] " << log_line;
      break;
    }
    default: {
      LOG(ERROR) << "AbslLogger received an invalid log level: " << level;
      LOG(ERROR) << "[Driver] " << log_line;
      break;
    }
  }
}

absl::Status Wintun::IsWintunInitialized() {
  if (!EnsureLibraryExists().ok()) {
    absl::Status status =
        absl::FailedPreconditionError("TUN library not found");
    PpnStatusDetails details;
    details.set_detailed_error_code(PpnStatusDetails::LIBRARY_NOT_FOUND);
    ::privacy::krypton::utils::SetPpnStatusDetails(&status, details);
    return status;
  }
  return absl::OkStatus();
}

absl::Status Wintun::EnsureLibraryExists() {
  if (!wintun_) {
    LOG(ERROR) << "[Wintun] Googtun is not initialized";
    return absl::FailedPreconditionError("Googtun is not initialized");
  }
  return absl::OkStatus();
}

absl::Status Wintun::EnsureAdapterExists() {
  if (!adapter_) {
    LOG(ERROR) << "[Wintun] Adapter not found";
    return absl::FailedPreconditionError("Adapter not found");
  }
  return absl::OkStatus();
}

absl::Status Wintun::EnsureSessionExists() {
  if (!session_) {
    LOG(ERROR) << "[Wintun] Session not found";
    return absl::FailedPreconditionError("Session not found");
  }
  return absl::OkStatus();
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
