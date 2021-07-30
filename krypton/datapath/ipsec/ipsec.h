// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_H_

// IPsec is a VPN protocol suite.
// We use ESP packet format (RFC 4303) with AES-GCM 256 encryption (RFC 4106).
// GCM encryption takes a secret key, initialization vector, plaintext, and
// an input for Additional Authenticated Data.
// The encryption algorithm outputs a ciphertext and an authentication tag,
// which is the Integrity Check Value.

#include <cstdint>

#include "third_party/absl/base/attributes.h"
#include "third_party/absl/numeric/int128.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

constexpr size_t kKeyLen = 32;
constexpr size_t kIVLen = 8;
constexpr size_t kSaltLen = 4;
constexpr size_t kAESBlockSize = 16;

// Specified in RFC 4303, Sections 2.1 - 2.3.
// We only ever send a 32-bit sequence number.
// IKEv2 uses 64-bit ESN by default, so if we're doing that, we'll only send the
// low-order bits as per Section 2.2.1.
//
// All fields are big-endian.
struct EspHeader {
  uint32_t client_spi;
  uint32_t sequence_number;
  char initialization_vector[kIVLen];
} ABSL_ATTRIBUTE_PACKED;

// Specified in RFC 4303, Section 2.8.
struct EspTrailer {
  absl::uint128 integrity_check_value;
} ABSL_ATTRIBUTE_PACKED;

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_H_
