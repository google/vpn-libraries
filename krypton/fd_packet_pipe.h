// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
#define PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_

#include <atomic>
#include <thread>  //NOLINT

#include "privacy/net/krypton/datapath/android_ipsec/event_fd.h"
#include "privacy/net/krypton/datapath/android_ipsec/events_helper.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/strings/substitute.h"

namespace privacy {
namespace krypton {

// A PacketPipe that's backed by a file descriptor.
class FdPacketPipe : public PacketPipe {
 public:
  explicit FdPacketPipe(int fd)
      : fd_(fd), thread_(absl::StrCat("FdPacketPipe{FD=", fd, "}")) {}

  ~FdPacketPipe() override;

  absl::Status WritePacket(const Packet& packet) override;

  void ReadPackets(std::function<bool(absl::Status, Packet)> handler) override
      ABSL_LOCKS_EXCLUDED(mutex_);

  absl::StatusOr<int> GetFd() const override { return fd_; }

  void Close() override;

  absl::Status StopReadingPackets() override ABSL_LOCKS_EXCLUDED(mutex_);

  std::string DebugString() override { return absl::StrCat("FD=", fd_); }

  bool SocketListeningTestOnly() const { return started_listening_; }

 private:
  // Start of the thread.
  absl::Status SetupReading() ABSL_LOCKS_EXCLUDED(mutex_);
  void Run() ABSL_LOCKS_EXCLUDED(mutex_);
  absl::Status RunInternal();
  void PostDatapathFailure(const absl::Status& status)
      ABSL_LOCKS_EXCLUDED(mutex_);
  void PostDatapathEstablished();

  int fd_;

  absl::Mutex mutex_;
  bool reading_ ABSL_GUARDED_BY(mutex_) = false;
  absl::CondVar reading_stopped_ ABSL_GUARDED_BY(mutex_);
  std::function<bool(absl::Status, Packet)> handler_;

  utils::LooperThread thread_;
  datapath::android::EventsHelper events_helper_;
  datapath::android::EventFd shutdown_event_;

  std::atomic_bool permanent_failure_notification_raised_ = false;
  std::atomic_bool started_listening_ = false;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_FD_PACKET_PIPE_H_
