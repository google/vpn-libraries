// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/pal/packet_pipe.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/synchronization/mutex.h"

namespace privacy {
namespace krypton {

// A PacketPipe that's backed by a file descriptor.
class FdPacketPipe : public PacketPipe {
 public:
  explicit FdPacketPipe(int fd)
      : fd_(fd), thread_(absl::StrCat("FdPacketPipe{FD=", fd, "}")) {}

  ~FdPacketPipe() override;

  absl::Status WritePackets(std::vector<Packet> packets) override;

  void ReadPackets(
      std::function<bool(absl::Status, std::vector<Packet>)> handler) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<int> GetFd() const override { return fd_; }

  void Close() override;

  absl::Status StopReadingPackets() override ABSL_LOCKS_EXCLUDED(mutex_);

  std::string DebugString() override { return absl::StrCat("FD=", fd_); }

  bool SocketListeningTestOnly() const { return started_listening_; }

  // Connects the underlying socket fd to the given endpoint.
  // This should be called before calling WritePackets.
  absl::Status Connect(const Endpoint& endpoint);

 private:
  // Start of the thread.
  absl::Status SetupReading() ABSL_LOCKS_EXCLUDED(mutex_);
  void Run() ABSL_LOCKS_EXCLUDED(mutex_);
  absl::Status RunInternal();
  void PostDatapathFailure(const absl::Status& status)
      ABSL_LOCKS_EXCLUDED(mutex_);

  int fd_;

  absl::Mutex mutex_;
  bool reading_ ABSL_GUARDED_BY(mutex_) = false;
  absl::CondVar reading_stopped_ ABSL_GUARDED_BY(mutex_);
  std::function<bool(absl::Status, std::vector<Packet>)> handler_;

  utils::LooperThread thread_;
  datapath::android::EventsHelper events_helper_;
  std::unique_ptr<datapath::android::EventFd> shutdown_event_
      ABSL_GUARDED_BY(mutex_);

  std::atomic_bool permanent_failure_notification_raised_ = false;
  std::atomic_bool started_listening_ = false;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
