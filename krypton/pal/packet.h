// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_PAL_PACKET_H_
#define PRIVACY_NET_KRYPTON_PAL_PACKET_H_

#include <functional>
#include <utility>

#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {

enum class IPProtocol {
  kUnknown = 0,
  kIPv4 = 1,
  kIPv6 = 2,
};

using PacketCleanup = std::function<void(void)>;

// Represents the byte data for a single network packet. Packet is designed to
// allow passing packet data throughout Krypton with an absolute minimum number
// of copying. Because of this, the data backing a packet may have been
// allocated in any manner. If may have been malloc'd, or it may be from an
// NSData. So, when constructing a Packet, it's necessary to provide a cleanup
// function that can be responsible for retaining the underlying data structure
// and releasing it when the Packet is destroyed.
class Packet {
 public:
  /**
   * Constructs an empty packet.
   */
  Packet() : protocol_(IPProtocol::kUnknown) {}

  /**
   * Constructs a packet backed by the given bytes. It's up to the producer and
   * consumer of the packet to agree on the packet's data's valid lifetime. The
   * cleanup function will be called when this packet is constructed, so it can
   * be used to own and clean up the bytes underlying this packet, if desired.
   */
  Packet(const char* data, int length, IPProtocol protocol,
         PacketCleanup cleanup)
      : data_(data),
        length_(length),
        protocol_(protocol),
        cleanup_(std::move(cleanup)) {}

  // Disallow copy and assign, since we don't know how the original data was
  // allocated, and don't want to make copies of it.
  Packet(const Packet& other) = delete;
  Packet& operator=(const Packet& other) = delete;

  Packet(Packet&& other) {
    data_ = other.data_;
    length_ = other.length_;
    protocol_ = other.protocol_;
    cleanup_ = std::move(other.cleanup_);

    other.data_ = nullptr;
    other.length_ = 0;
    other.cleanup_ = []() {};
  }

  Packet& operator=(Packet&& other) {
    // Clean up the existing data before overwriting it.
    cleanup_();

    data_ = other.data_;
    length_ = other.length_;
    protocol_ = other.protocol_;
    cleanup_ = std::move(other.cleanup_);

    other.data_ = nullptr;
    other.length_ = 0;
    other.cleanup_ = []() {};

    return *this;
  }

  virtual ~Packet() { cleanup_(); }

  absl::string_view data() const { return absl::string_view(data_, length_); }

  IPProtocol protocol() const { return protocol_; }

 private:
  // The raw bytes data for a single packet.
  const char* data_;
  size_t length_;

  // The protocol of the packet data.
  IPProtocol protocol_;

  // A function to call when this packet object is destroyed.
  PacketCleanup cleanup_ = []() {};
};


}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_PACKET_H_
