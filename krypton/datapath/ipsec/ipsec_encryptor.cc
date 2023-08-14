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

#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"

#include <cstddef>
#include <cstring>
#include <limits>

#include "privacy/net/krypton/datapath/ipsec/ipsec.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/aead.h"

#ifdef _WIN32
#include <winsock2.h>
#define IPPROTO_IPIP 4
#define IPPROTO_IPV6 41
#else
#include <netinet/in.h>
#endif

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "base/logging.h"
#include "privacy/net/krypton/crypto/ipsec_forward_secure_random.h"
#include "privacy/net/krypton/crypto/openssl_error.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_packet.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_packet_pool.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"

#undef htobe32

#ifdef __APPLE__
#define htobe32(x) OSSwapHostToBigInt32((x))
#else
#define htobe32(x) htonl((x))
#endif

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

/* static */ absl::StatusOr<std::unique_ptr<IpSecEncryptor>>
IpSecEncryptor::Create(uint32_t spi, const TransformParams& params) {
  if (!params.has_ipsec()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams is null";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams is null");
  }
  const auto& ipsec_param = params.ipsec();

  if (!ipsec_param.has_uplink_key()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has no uplink_key";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has no uplink_key");
  }
  if (!ipsec_param.has_uplink_salt()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has no uplink_salt";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has no uplink_salt");
  }
  const auto key =
      reinterpret_cast<const uint8_t*>(ipsec_param.uplink_key().data());
  const auto key_size = ipsec_param.uplink_key().size();
  if (key_size != kKeyLen) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has a uplink_key "
                  "with wrong size";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has a uplink_key with wrong "
        "size");
  }

  auto aead_ctx =
      EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), key, key_size, kEspTagLen);
  if (aead_ctx == nullptr) {
    LOG(ERROR) << "EVP_AEAD_CTX_new failure: keysize=" << key_size;
    return crypto::GetOpenSSLError("EVP_AEAD_CTX_new failure");
  }
  if (ipsec_param.uplink_salt().size() != kSaltLen) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has a uplink_salt "
                  "with wrong size";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has a uplink_salt with wrong "
        "size");
  }
  std::string salt = ipsec_param.uplink_salt();

  return std::make_unique<IpSecEncryptor>(aead_ctx, salt, spi);
}

absl::Status IpSecEncryptor::Encrypt(absl::string_view input,
                                     IPProtocol protocol, IpSecPacket* output) {
  const auto output_data = reinterpret_cast<uint8_t*>(output->data());
  const auto input_data = reinterpret_cast<const uint8_t*>(input.begin());

  // Assign nonce for encryption.
  if (sequence_number_ == std::numeric_limits<uint32_t>::max()) {
    // Even though we use random IVs, after 2^32 invocations the probability of
    // nonce reuse becomes concerning, so we should fail safe.
    // copybara:strip_begin(internal link)
    // See http://yaqs/2961540066972794880#a1 for ise-crypto recommendation.
    // copybara:strip_end
    return absl::InternalError("Encryptor expired before rekey occurred");
  }
  auto initialization_vector = crypto::CreateSecureRandomString(kIVLen);
  char nonce[kSaltLen + kIVLen];

  // If no protocol was specified, try to infer it from the packet data.
  if (protocol == IPProtocol::kUnknown) {
    if (input.empty()) {
      return absl::InternalError("Empty packet to encrypt");
    }
    uint8_t version = static_cast<uint8_t>(*input.data()) >> 4;
    switch (version) {
      case 4:
        protocol = IPProtocol::kIPv4;
        break;
      case 6:
        protocol = IPProtocol::kIPv6;
        break;
      default:
        // Leave it as-is.
        break;
    }
  }

  uint8_t next_header;
  if (protocol == IPProtocol::kIPv4) {
    next_header = IPPROTO_IPIP;
  } else if (protocol == IPProtocol::kIPv6) {
    next_header = IPPROTO_IPV6;
  } else {
    LOG(ERROR) << "Packet with unexpected IPProtocol";
    return absl::InternalError("Packet with unexpected IPProtocol");
  }

  // RFC 4303 ESP packet format.
  // 0                   1                   2                   3
  // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
  // |               Security Parameters Index (SPI)                 | ^Int.
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
  // |                      Sequence Number                          | |ered
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
  // |                    Payload Data* (variable)                   | |   ^
  // ~                                                               ~ |   |
  // |                                                               | |Conf.
  // +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
  // |               |     Padding (0-255 bytes)                     | |ered*
  // +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
  // |                               |  Pad Length   | Next Header   | v   v
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
  // |         Integrity Check Value-ICV   (variable)                |
  // ~                                                               ~
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // Expects an IP (tunnel mode) or L4 (transport mode) packet, already parsed.
  //
  // 1 for pad length and 1 for the next header.
  const int plaintext_len = input.size() + 2;

  const int pad_len =
      (kAESBlockSize - (plaintext_len % kAESBlockSize)) % kAESBlockSize;

  if (plaintext_len + pad_len > output->max_data_size()) {
    LOG(ERROR) << "Input packet is too large to be encrypted";
    return absl::InternalError("Input packet is too large to be encrypted");
  }

  memcpy(output_data, input_data, input.size());

  // Add monotonically increasing padding (RFC 4303 section 2.4)
  auto* pad = output_data + input.size();
  for (int i = 1; i <= pad_len; ++i) {
    *pad++ = i;
  }

  auto* padlen_nexthdr = pad;
  padlen_nexthdr[0] = pad_len;
  padlen_nexthdr[1] = next_header;

  // Encrypted packet data size.
  CHECK_EQ(initialization_vector.size(), kIVLen);
  memcpy(nonce, salt_->c_str(), kSaltLen);
  memcpy(nonce + kSaltLen, initialization_vector.c_str(), kIVLen);

  uint32_t sequence_number = htobe32(sequence_number_++);
  uint32_t spi = htobe32(spi_);
  char aad[sizeof(spi) + sizeof(sequence_number)];
  memcpy(aad, &spi, sizeof(spi));
  memcpy(aad + sizeof(spi), &sequence_number, sizeof(sequence_number));
  const auto aad_head = reinterpret_cast<const uint8_t*>(aad);

  // Encrypt the data stored in the `data_head`, then write the result to the
  // `packet_head`.
  size_t dst_len;
  if (EVP_AEAD_CTX_seal(aead_ctx_.get(), output_data, &dst_len,
                        output->max_data_size(),
                        reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce),
                        output_data, plaintext_len + pad_len, aad_head,
                        sizeof(spi) + sizeof(sequence_number)) != 1) {
    LOG(ERROR) << "EVP_AEAD_CEVP_AEAD_CTX_seal failed";
    return crypto::GetOpenSSLError("EVP_AEAD_CTX_seal failure");
  }
  output->header()->client_spi = spi;
  output->header()->sequence_number = sequence_number;
  memcpy(output->header()->initialization_vector, initialization_vector.c_str(),
         kIVLen);

  CHECK_GE(dst_len, 0);
  output->resize_data(dst_len);

  return absl::OkStatus();
}

absl::StatusOr<Packet> Encryptor::Process(const Packet& packet) {
  auto output = packet_pool_.Borrow();
  if (!output) {
    LOG(INFO) << "Dropping an uplink packet.";
    return absl::ResourceExhaustedError("packet pool is exhausted");
  }

  PPN_RETURN_IF_ERROR(
      encryptor_->Encrypt(packet.data(), packet.protocol(), output.get()));

  // The pool won't be destroyed until all packets have been returned, so it's
  // safe to capture a pointer to it here.
  return Packet(output->buffer(), output->buffer_size(), packet.protocol(),
                [output] {});
}

/* static */ absl::StatusOr<std::unique_ptr<Encryptor>> Encryptor::Create(
    uint32_t spi, const TransformParams& params) {
  PPN_ASSIGN_OR_RETURN(auto encryptor, IpSecEncryptor::Create(spi, params));
  return std::make_unique<Encryptor>(std::move(encryptor));
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
