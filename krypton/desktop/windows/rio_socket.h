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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_RIO_SOCKET_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_RIO_SOCKET_H_

// clang-format off
#include <Windows.h>
#include <winsock2.h>
#include <mswsock.h>
// clang-format on

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/socket_interface.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {
namespace windows {

// Socket implementation that uses Registered I/O APIs.
// This class is not thread-safe.
class RioSocket : public SocketInterface {
 public:
  RioSocket(Endpoint src_endpoint, int interface_index)
      : src_endpoint_(src_endpoint), interface_index_(interface_index) {}

  ~RioSocket() override {
    LOG(INFO) << "Destroying RioSocket";
    if (socket_ != INVALID_SOCKET) {
      LOG(WARNING) << "Destructor called when RioSocket was not stopped, "
                      "stopping socket";
      PPN_LOG_IF_ERROR(Close());
    }
  }

  // Disallow copy and move, so that we don't close a copy of an active socket.
  RioSocket(const RioSocket&) = delete;
  RioSocket(RioSocket&&) = delete;
  RioSocket& operator=(const RioSocket&) = delete;
  RioSocket& operator=(RioSocket&&) = delete;

  // Creates a RIO socket and everything needed to do I/O.
  // This should only be called once.
  absl::Status Open() ABSL_LOCKS_EXCLUDED(rq_mutex_);

  // Stops the socket and cancels any pending operations.
  // Callers should not restart a stopped RioSocket.
  absl::Status Close() override;

  // Reads packets from the underlying socket.
  absl::StatusOr<std::vector<Packet>> ReadPackets() override
      ABSL_LOCKS_EXCLUDED(rq_mutex_);

  // Writes packets to the socket and sends them to the connected address.
  absl::Status WritePackets(std::vector<Packet> packets) override
      ABSL_LOCKS_EXCLUDED(rq_mutex_);

  // Connects the underlying socket to a remote address.
  // This should be called after Start and before any Read/WritePackets calls.
  absl::Status Connect(Endpoint dest) override;

  void GetDebugInfo(DatapathDebugInfo* debug_info) override {
    debug_info->set_uplink_packets_dropped(uplink_packets_dropped_);
  }

 private:
  // Send and receive queues use completions to track the memory used for each
  // packet. DequeueCompletions returns the finished completions in a queue.
  const DWORD kCompletionQueueSize = 1024;

  // Wrapper class for the buffer's raw memory pointer.
  // Input buffer must be constructed with RioSocket::AllocateBuffer.
  class RioBuffer {
   public:
    RioBuffer(char* buffer, uint64_t buffer_size)
        : buffer_(buffer), buffer_size_(buffer_size) {}
    ~RioBuffer() { FreeBuffer(buffer_); }

    // Disallow copy.
    RioBuffer(const RioBuffer&) = delete;
    RioBuffer& operator=(const RioBuffer&) = delete;

    // Returns a pointer to the specified packet in the buffer.
    char* GetOffset(uint64_t offset) {
      if (offset >= buffer_size_) {
        LOG(FATAL) << "Requested offset " << offset << " exceeds buffer size "
                   << buffer_size_;
        return nullptr;
      }
      return buffer_ + offset;
    }

   private:
    char* buffer_ = nullptr;
    uint64_t buffer_size_ = 0;
  };

  // Create a Winsock socket. Flags are used to specify additional attributes.
  absl::Status CreateWSASocket(int flags);

  // Create a Registered I/O completion queue. The queue stores pending ops and
  // signals the notification when completions are available.
  absl::StatusOr<RIO_CQ> CreateRIOCompletionQueue(
      PRIO_NOTIFICATION_COMPLETION completion);

  // Create a Registered I/O request queue.
  // The queue links a socket and completion queues.
  // This must be called before using any RIO I/O functions.
  absl::StatusOr<RIO_RQ> CreateRIORequestQueue();

  // Allocates a backing buffer for RIO completion queues.
  absl::StatusOr<char*> AllocateBuffer(DWORD buffer_size);

  // Registers a buffer with RIO, locking the pages into physical memory.
  absl::StatusOr<RIO_BUFFERID> RegisterBuffer(char* buffer, DWORD buffer_size);

  // Frees a buffer allocated with AllocateBuffer.
  static void FreeBuffer(char* buffer);

  // Closes resources in RIO_NOTIFICATION_COMPLETION.
  void CleanupNotificationCompletion(RIO_NOTIFICATION_COMPLETION completion);

  // Adds a RIOReceive request to the receive completion queue.
  absl::Status InsertReceiveRequest() ABSL_LOCKS_EXCLUDED(rq_mutex_);

  // Returns an index into send_slices_ that corresponds to a sending packet.
  absl::StatusOr<uint32_t> GetSendBufferIndex();

  SOCKET socket_ = INVALID_SOCKET;
  HANDLE close_handle_ = nullptr;

  // rq_mutex protects the request queue, which is shared between RIOSend and
  // RIOReceive calls.
  absl::Mutex rq_mutex_;

  // Socket variables.
  Endpoint src_endpoint_;
  int interface_index_;

  // RIO variables.
  RIO_EXTENSION_FUNCTION_TABLE rio_table_ = {};
  RIO_RQ request_queue_ ABSL_GUARDED_BY(rq_mutex_);

  RIO_CQ send_completion_queue_;
  RIO_NOTIFICATION_COMPLETION send_completion_;
  std::unique_ptr<RioBuffer> send_buffer_;
  RIO_BUFFERID send_buffer_id_;
  std::vector<RIO_BUF> send_slices_;
  std::vector<RIORESULT> send_completions_;
  uint32_t send_buffer_head_ = 0;
  uint32_t send_buffer_tail_ = 0;
  bool send_buffer_full_ = false;
  std::atomic_int64_t uplink_packets_dropped_ = 0;

  RIO_CQ receive_completion_queue_;
  RIO_NOTIFICATION_COMPLETION receive_completion_;
  std::unique_ptr<RioBuffer> receive_buffer_;
  RIO_BUFFERID receive_buffer_id_;
  std::vector<RIO_BUF> receive_slices_;
  std::vector<RIORESULT> receive_completions_;
  uint32_t receive_buffer_head_ = 0;
  uint32_t receive_buffer_tail_ = 0;
  bool receive_buffer_full_ = false;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_RIO_SOCKET_H_
