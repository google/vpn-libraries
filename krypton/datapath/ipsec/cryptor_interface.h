// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_CRYPTOR_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_CRYPTOR_INTERFACE_H_

#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

/// Common interface for how a packet is encrypted/decrypted in the IPsec
/// datapath.
class CryptorInterface {
 public:
  virtual ~CryptorInterface() = default;

  // Encrypts/Decrypts the packet.
  //
  // Encryption could potentially change the size of the passed-in packet,
  // therefore it's unsafe to write the packet back to the same memory address.
  // After encryption, a new packet will be created and returned.
  virtual absl::StatusOr<Packet> Process(const Packet& packet) = 0;
};

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_CRYPTOR_INTERFACE_H_
