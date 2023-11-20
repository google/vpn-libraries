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

#include "privacy/net/krypton/desktop/windows/rio_socket.h"

// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <netioapi.h>
#include <VersionHelpers.h>
#include <memoryapi.h>
// clang-format on

#include <cstdint>
#include <memory>
#include <vector>

#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

using ::privacy::krypton::utils::IPRange;

namespace privacy {
namespace krypton {
namespace windows {

const int kMaxPacketSize = 1600;
// The maximum number of completions that RIODequeueCompletions can return.
const int kMaxCompletionResults = 1024;

absl::Status RioSocket::Open() {
  // Check the version for RIO support.
  if (!IsWindows8OrGreater()) {
    LOG(ERROR) << "RIO requires Windows 8 or greater";
    return absl::FailedPreconditionError("RIO requires Windows 8 or greater");
  }

  // Initialize a temporary socket for WSAIoctl.
  auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) {
    return absl::InternalError("socket failed");
  }
  absl::Cleanup socket_closer = [s] { closesocket(s); };

  // Get the RIO function table from Winsock.
  GUID multiple_rio = WSAID_MULTIPLE_RIO;
  DWORD bytes;
  int result =
      WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
               reinterpret_cast<void *>(&multiple_rio), sizeof(multiple_rio),
               &rio_table_, sizeof(rio_table_), &bytes, nullptr, 0);
  if (result == SOCKET_ERROR) {
    return utils::GetStatusForError("WSAIoctl failed", WSAGetLastError());
  }

  // Create a RIO socket.
  PPN_RETURN_IF_ERROR(CreateWSASocket(/* flags = */ WSA_FLAG_REGISTERED_IO));

  // Populate RIO_NOTIFICATION_COMPLETION structs.
  send_completion_.Type = RIO_EVENT_COMPLETION;
  PPN_ASSIGN_OR_RETURN(send_completion_.Event.EventHandle,
                       utils::CreateManualResetEvent());
  send_completion_.Event.NotifyReset = TRUE;

  receive_completion_.Type = RIO_EVENT_COMPLETION;
  PPN_ASSIGN_OR_RETURN(receive_completion_.Event.EventHandle,
                       utils::CreateManualResetEvent());
  receive_completion_.Event.NotifyReset = TRUE;

  // Create RIO completion queues for input & output.
  // RIO uses completion queues to notify the application of pending I/O.
  PPN_ASSIGN_OR_RETURN(send_completion_queue_,
                       CreateRIOCompletionQueue(&send_completion_));
  PPN_ASSIGN_OR_RETURN(receive_completion_queue_,
                       CreateRIOCompletionQueue(&receive_completion_));
  LOG(INFO) << "Created completion queues";

  // Create RIO request queue.
  {
    absl::MutexLock l(&rq_mutex_);
    PPN_ASSIGN_OR_RETURN(request_queue_, CreateRIORequestQueue());
    LOG(INFO) << "Created request queue";
  }

  // Allocate and register buffers.
  DWORD buffer_size = kMaxPacketSize * kCompletionQueueSize;
  PPN_ASSIGN_OR_RETURN(char *send_buffer_ptr, AllocateBuffer(buffer_size));
  PPN_ASSIGN_OR_RETURN(char *receive_buffer_ptr, AllocateBuffer(buffer_size));
  PPN_ASSIGN_OR_RETURN(send_buffer_id_,
                       RegisterBuffer(send_buffer_ptr, buffer_size));
  PPN_ASSIGN_OR_RETURN(receive_buffer_id_,
                       RegisterBuffer(receive_buffer_ptr, buffer_size));
  send_buffer_ = std::make_unique<RioBuffer>(send_buffer_ptr, buffer_size);
  receive_buffer_ =
      std::make_unique<RioBuffer>(receive_buffer_ptr, buffer_size);
  LOG(INFO) << "Registered buffers";

  // Allocate memory for RIO_BUF arrays.
  // These track the slices of memory used by RIO completions.
  send_slices_.resize(kCompletionQueueSize);
  receive_slices_.resize(kCompletionQueueSize);

  // Allocate memory for RIORESULT arrays.
  // These contain information about completion results.
  send_completions_.resize(kMaxCompletionResults);
  receive_completions_.resize(kMaxCompletionResults);

  // Pre-populate the receive buffer with pending receives.
  for (int i = 0; i < kCompletionQueueSize; i++) {
    PPN_RETURN_IF_ERROR(InsertReceiveRequest());
  }

  // We're using events to receive RIO completions.
  // This lets us stop the socket cleanly when we're waiting for I/O.
  // In the future, we may want to use IOCP instead of events.
  // IOCP's advantage is in multithreading.
  PPN_ASSIGN_OR_RETURN(close_handle_, utils::CreateManualResetEvent());
  return absl::OkStatus();
}

absl::Status RioSocket::Close() {
  LOG(INFO) << "Closing RioSocket";
  // Signal close handle.
  SetEvent(close_handle_);

  // Close completion queues.
  rio_table_.RIOCloseCompletionQueue(send_completion_queue_);
  rio_table_.RIOCloseCompletionQueue(receive_completion_queue_);

  // Close notification handles.
  CleanupNotificationCompletion(send_completion_);
  CleanupNotificationCompletion(receive_completion_);

  // Deregister buffers.
  rio_table_.RIODeregisterBuffer(send_buffer_id_);
  rio_table_.RIODeregisterBuffer(receive_buffer_id_);

  // Deallocate buffers.
  send_buffer_.reset();
  receive_buffer_.reset();
  send_slices_.clear();
  receive_slices_.clear();
  send_completions_.clear();
  receive_completions_.clear();

  // Closing the socket will also close the request queue.
  closesocket(socket_);
  socket_ = INVALID_SOCKET;
  CloseHandle(close_handle_);
  return absl::OkStatus();
}

absl::StatusOr<std::vector<Packet>> RioSocket::ReadPackets() {
  // Call RIONotify to receive notifications when a completion occurs.
  (void)rio_table_.RIONotify(receive_completion_queue_);

  // Wait on completion event and stop event.
  HANDLE handles[2] = {close_handle_, receive_completion_.Event.EventHandle};
  DWORD wait_result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
  switch (wait_result) {
    case WAIT_OBJECT_0 + 0: {
      // The stop handle is signaled.
      return absl::CancelledError("Cancelled wait for RioSocket::ReadPackets");
    }
    case WAIT_OBJECT_0 + 1: {
      // There are pending completions, so we'll dequeue them.
      break;
    }
    default: {
      return utils::GetStatusForError("WaitForMultipleObjects failed",
                                      GetLastError());
    }
  }

  // Dequeue completions.
  ULONG completed_reads = rio_table_.RIODequeueCompletion(
      receive_completion_queue_, receive_completions_.data(),
      kMaxCompletionResults);
  if (completed_reads == RIO_CORRUPT_CQ || completed_reads == 0) {
    return utils::GetStatusForError("ReadPackets: RIODequeueCompletion failed",
                                    WSAGetLastError());
  }

  // Move the receive buffer.
  receive_buffer_head_ =
      (receive_buffer_head_ + completed_reads) % kCompletionQueueSize;
  if (receive_buffer_full_) {
    receive_buffer_full_ = false;
  }

  // Re-queue receive requests.
  for (int i = 0; i < completed_reads; i++) {
    PPN_LOG_IF_ERROR(InsertReceiveRequest());
  }

  // Create packet vector.
  std::vector<Packet> packets;

  for (int i = 0; i < completed_reads; i++) {
    RIO_BUF *packet_buf =
        reinterpret_cast<RIO_BUF *>(receive_completions_[i].RequestContext);
    ULONG packet_size = receive_completions_[i].BytesTransferred;

    // Convert buffer into a Krypton Packet.
    // TODO: use a packet pool to avoid the copy_packet malloc
    char *rio_packet = receive_buffer_->GetOffset(packet_buf->Offset);
    char *copy_packet = new char[packet_size];
    memcpy(copy_packet, rio_packet, packet_size);
    packets.emplace_back(const_cast<const char *>(copy_packet), packet_size,
                         IPProtocol::kUnknown,
                         [copy_packet]() { delete[] copy_packet; });
  }
  return packets;
}

absl::Status RioSocket::WritePackets(std::vector<Packet> packets) {
  // Copy each packet into a RIO_BUF and send with RIOSend.
  for (const auto &packet : packets) {
    if (packet.data().length() > kMaxPacketSize) {
      LOG(ERROR) << "Max packet size is " << kMaxPacketSize
                 << " bytes, received packet with size "
                 << packet.data().length();
      uplink_packets_dropped_++;
      continue;
    }

    // Dequeue send completions to make room in the send buffer.
    ULONG completed_sends = rio_table_.RIODequeueCompletion(
        send_completion_queue_, send_completions_.data(),
        kMaxCompletionResults);
    if (completed_sends == RIO_CORRUPT_CQ) {
      return utils::GetStatusForError(
          "WritePackets: RIODequeueCompletion failed", WSAGetLastError());
    }
    if (completed_sends != 0) {
      send_buffer_head_ =
          (send_buffer_head_ + completed_sends) % kCompletionQueueSize;
      if (send_buffer_full_) {
        send_buffer_full_ = false;
      }
    }

    auto buffer_index = GetSendBufferIndex();
    if (!buffer_index.ok()) {
      LOG(ERROR) << buffer_index.status();
      uplink_packets_dropped_++;
      continue;
    }
    uint32_t offset = *buffer_index * kMaxPacketSize;
    send_slices_[*buffer_index].BufferId = send_buffer_id_;
    send_slices_[*buffer_index].Length = packet.data().length();
    send_slices_[*buffer_index].Offset = *buffer_index * kMaxPacketSize;
    memcpy(send_buffer_->GetOffset(offset), packet.data().data(),
           packet.data().length());
    {
      absl::MutexLock l(&rq_mutex_);
      BOOL send_result =
          rio_table_.RIOSend(request_queue_, &send_slices_[*buffer_index], 1, 0,
                             &send_slices_[*buffer_index]);
      if (!send_result) {
        return utils::GetStatusForError("RIOSend failed", WSAGetLastError());
      }
    }
  }
  return absl::OkStatus();
}

absl::Status RioSocket::Connect(Endpoint dest) {
  LOG(INFO) << "RIO socket connecting to " << dest.ToString();
  sockaddr_storage dst_addr;
  socklen_t dst_addr_size;
  int dst_port = dest.port();

  PPN_ASSIGN_OR_RETURN(auto dst_range, IPRange::Parse(dest.address()));
  PPN_RETURN_IF_ERROR(
      dst_range.GenericAddress(dst_port, &dst_addr, &dst_addr_size));

  if (connect(socket_, reinterpret_cast<struct sockaddr *>(&dst_addr),
              dst_addr_size) != 0) {
    return utils::GetStatusForError("connect failed", WSAGetLastError());
  }
  LOG(INFO) << "RIO socket connected.";
  return absl::OkStatus();
}

absl::Status RioSocket::CreateWSASocket(int flags) {
  LOG(INFO) << "Creating WSA socket";
  int family =
      (src_endpoint_.ip_protocol() == IPProtocol::kIPv4 ? AF_INET : AF_INET6);

  int src_port = src_endpoint_.port();
  sockaddr_storage src_addr;
  socklen_t src_addr_size;

  PPN_ASSIGN_OR_RETURN(auto src_range, IPRange::Parse(src_endpoint_.address()));
  PPN_RETURN_IF_ERROR(
      src_range.GenericAddress(src_port, &src_addr, &src_addr_size));

  // Create a RIO socket.
  socket_ = WSASocket(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, flags);
  if (socket_ == INVALID_SOCKET) {
    return utils::GetStatusForError("WSASocket failed", WSAGetLastError());
  }

  // Bind socket.
  if (bind(socket_, reinterpret_cast<sockaddr *>(&src_addr), src_addr_size) ==
      SOCKET_ERROR) {
    return utils::GetStatusForError("bind failed", WSAGetLastError());
  }

  // Attach socket to Wintun network interface.
  if (family == AF_INET) {
    // Argument to setsockopt must be a string in network byte order.
    DWORD dwIndex = htonl(interface_index_);
    if (setsockopt(socket_, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<char *>(&dwIndex), sizeof(dwIndex)) != 0) {
      return utils::GetStatusForError("setsockopt failed for IPPROTO_IP",
                                      WSAGetLastError());
    }
  } else if (family == AF_INET6) {
    // For IPv6, the equivalent value must be specified in host order. Really.
    DWORD dwIndex = interface_index_;
    if (setsockopt(socket_, IPPROTO_IPV6, IPV6_UNICAST_IF,
                   reinterpret_cast<char *>(&dwIndex), sizeof(dwIndex)) != 0) {
      return utils::GetStatusForError("setsockopt failed for IPPROTO_IPV6",
                                      WSAGetLastError());
    }
  }

  LOG(INFO) << "Created WSA socket";
  return absl::OkStatus();
}

absl::StatusOr<RIO_CQ> RioSocket::CreateRIOCompletionQueue(
    PRIO_NOTIFICATION_COMPLETION completion) {
  RIO_CQ cq =
      rio_table_.RIOCreateCompletionQueue(kCompletionQueueSize, completion);
  if (cq == RIO_INVALID_CQ) {
    return utils::GetStatusForError("RIOCreateCompletionQueue failed",
                                    WSAGetLastError());
  }
  return cq;
}

absl::StatusOr<RIO_RQ> RioSocket::CreateRIORequestQueue() {
  RIO_RQ rq = rio_table_.RIOCreateRequestQueue(
      socket_, kCompletionQueueSize, /* MaxReceiveDataBuffers = */ 1,
      kCompletionQueueSize, /* MaxSendDataBuffers = */ 1,
      receive_completion_queue_, send_completion_queue_,
      /* SocketContext = */ nullptr);
  if (rq == RIO_INVALID_RQ) {
    return utils::GetStatusForError("RIOCreateRequestQueue failed",
                                    WSAGetLastError());
  }
  return rq;
}

absl::StatusOr<char *> RioSocket::AllocateBuffer(DWORD buffer_size) {
  auto allocate_success = reinterpret_cast<char *>(
      VirtualAlloc(0, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (allocate_success == NULL) {
    return utils::GetStatusForError("VirtualAlloc failed", GetLastError());
  }
  return allocate_success;
}

absl::StatusOr<RIO_BUFFERID> RioSocket::RegisterBuffer(char *buffer,
                                                       DWORD buffer_size) {
  RIO_BUFFERID register_success =
      rio_table_.RIORegisterBuffer(buffer, buffer_size);
  if (register_success == RIO_INVALID_BUFFERID) {
    return utils::GetStatusForError("RIORegisterBuffer failed",
                                    WSAGetLastError());
  }
  return register_success;
}

void RioSocket::FreeBuffer(char *buffer) {
  BOOL free_success = VirtualFree(buffer, /* dwSize = */ 0, MEM_RELEASE);
  if (free_success == 0) {
    LOG(ERROR) << "VirtualFree failed: "
               << utils::GetStatusForError("VirtualFree failed",
                                           GetLastError());
  }
}

void RioSocket::CleanupNotificationCompletion(
    RIO_NOTIFICATION_COMPLETION completion) {
  if (completion.Type == RIO_EVENT_COMPLETION) {
    CloseHandle(completion.Event.EventHandle);
  }
}

absl::Status RioSocket::InsertReceiveRequest() {
  // Check if the receive ring buffer is full.
  if (receive_buffer_full_) {
    return absl::ResourceExhaustedError("Receive buffer is full");
  }
  uint32_t buffer_index = receive_buffer_tail_;
  receive_buffer_tail_ = (receive_buffer_tail_ + 1) % kCompletionQueueSize;
  if ((receive_buffer_head_ % kCompletionQueueSize) ==
      (receive_buffer_tail_ % kCompletionQueueSize)) {
    receive_buffer_full_ = true;
  }

  // Populate RIO_BUF entry. This is passed as the RequestContext field.
  receive_slices_[buffer_index].BufferId = receive_buffer_id_;
  receive_slices_[buffer_index].Offset = buffer_index * kMaxPacketSize;
  receive_slices_[buffer_index].Length = kMaxPacketSize;

  absl::MutexLock l(&rq_mutex_);
  BOOL receive_result =
      rio_table_.RIOReceive(request_queue_, &receive_slices_[buffer_index], 1,
                            0, &receive_slices_[buffer_index]);
  if (!receive_result) {
    return utils::GetStatusForError("RIOReceive failed", WSAGetLastError());
  }
  return absl::OkStatus();
}

absl::StatusOr<uint32_t> RioSocket::GetSendBufferIndex() {
  if (send_buffer_full_) {
    return absl::ResourceExhaustedError("Send buffer is full");
  }
  uint32_t buffer_index = send_buffer_tail_;
  send_buffer_tail_ = (send_buffer_tail_ + 1) % kCompletionQueueSize;
  if ((send_buffer_head_ % kCompletionQueueSize) ==
      (send_buffer_tail_ % kCompletionQueueSize)) {
    send_buffer_full_ = true;
  }

  // Populate RIO_BUF entry. This is passed as the RequestContext field.
  send_slices_[buffer_index].BufferId = send_buffer_id_;
  send_slices_[buffer_index].Offset = buffer_index * kMaxPacketSize;
  send_slices_[buffer_index].Length = kMaxPacketSize;

  return buffer_index;
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
