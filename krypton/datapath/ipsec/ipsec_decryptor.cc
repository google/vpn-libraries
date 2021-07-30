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

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"

#include <netinet/in.h>

#include <cstdint>
#include <memory>

#include "base/logging.h"
#include "privacy/net/krypton/crypto/ipsec_forward_secure_random.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_packet.h"
#include "privacy/net/krypton/datapath/ipsec/openssl_error.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

absl::Status Decryptor::Start(const TransformParams& params) {
  return Rekey(params);
}

absl::StatusOr<Packet> Decryptor::Process(const Packet& packet) {
  if (packet.data().size() <= sizeof(EspHeader) + sizeof(EspTrailer)) {
    LOG(ERROR) << "Packet size is too small: " << packet.data().size();
    return absl::InvalidArgumentError("Packet size is too small");
  }
  IpSecPacket* output = new IpSecPacket();
  const auto ciphertext_length = packet.data().size() - sizeof(EspHeader);
  const auto plaintext_length = ciphertext_length;
  if (ciphertext_length > output->max_data_size()) {
    LOG(ERROR) << "Packet size is too large: " << packet.data().size();
    return absl::InvalidArgumentError("Packet size is too large");
  }
  auto input_header = const_cast<EspHeader*>(
      reinterpret_cast<const EspHeader*>(packet.data().data()));
  auto input_data = reinterpret_cast<uint8_t*>(
      const_cast<char*>(packet.data().data()) + sizeof(EspHeader));

  const auto packet_data = reinterpret_cast<uint8_t*>(output->data());
  if (packet_data == nullptr) {
    LOG(ERROR) << "Packet too short for AES256-GCM tag";
    return absl::InvalidArgumentError("Packet too short for GCM256 tag");
  }

  // Encryptors are responsible for ensuring these numbers are big-endian.
  auto spi = input_header->client_spi;
  auto sequence_number = input_header->sequence_number;
  CHECK_EQ(sizeof(input_header->initialization_vector), kIVLen);
  char aad[sizeof(spi) + sizeof(sequence_number)];
  memcpy(aad, &spi, sizeof(spi));
  memcpy(aad + sizeof(spi), &sequence_number, sizeof(sequence_number));
  const auto aad_head = reinterpret_cast<const uint8_t*>(aad);

  size_t dst_len;
  {
    absl::MutexLock l(&mutex_);
    if (!salt_) {
      LOG(ERROR) << "Downlink salt is null";
      return absl::InternalError("Uplink salt is null");
    }
    char nonce[kSaltLen + kIVLen];
    memcpy(nonce, salt_->c_str(), kSaltLen);
    memcpy(nonce + kSaltLen, &(input_header->initialization_vector), kIVLen);

    if (EVP_AEAD_CTX_open(aead_ctx_.get(), packet_data, &dst_len,
                          ciphertext_length,
                          reinterpret_cast<const uint8_t*>(&nonce),
                          sizeof(nonce), input_data, plaintext_length, aad_head,
                          sizeof(spi) + sizeof(sequence_number)) != 1) {
      LOG(ERROR) << "EVP_AEAD_CTX_open failed";
      return GetOpenSSLError("EVP_AEAD_CTX_open failed");
    }
  }
  output->resize_data(dst_len);
  if (dst_len < 2) {
    LOG(ERROR) << "Unexpected decrypted packet data with size: " << dst_len;
    return absl::InternalError("Unexpected decrypted packet data");
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
  auto pad_len_ptr = reinterpret_cast<uint8_t*>(output->data()) + dst_len - 2;
  const int pad_len = *pad_len_ptr;

  // Verify the next header is populated correctly.
  auto next_header =
      *(reinterpret_cast<uint8_t*>(output->data()) + dst_len - 1);
  auto ip_protocol = IPProtocol::kUnknown;
  if (next_header == IPPROTO_IPIP) {
    ip_protocol = IPProtocol::kIPv4;
  } else if (next_header == IPPROTO_IPV6) {
    ip_protocol = IPProtocol::kIPv6;
  }

  if (pad_len + 2 > dst_len) {
    LOG(ERROR) << "Packet has wrong padding: " << pad_len;
    return absl::InternalError("Packet has wrong padding");
  }

  // Verify the padding is populated correctly.
  auto count = pad_len;
  // Move to the last pad content.
  pad_len_ptr--;
  while (count > 0) {
    if (*pad_len_ptr != count) {
      LOG(ERROR) << "Packet has unexpected padding content";
      return absl::InternalError("Packet has unexpected padding content");
    }
    count--;
    pad_len_ptr--;
  }

  return Packet(output->data(), dst_len - pad_len - 2, ip_protocol,
                [output] { delete output; });
}

absl::Status Decryptor::Rekey(const TransformParams& params) {
  if (!params.has_ipsec()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams is null";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams is null");
  }
  auto ipsec_param = params.ipsec();

  if (!ipsec_param.has_downlink_key()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has no downlink_key";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has no downlink_key");
  }
  if (!ipsec_param.has_downlink_salt()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has no downlink_salt";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has no downlink_salt");
  }
  const auto key =
      reinterpret_cast<const uint8_t*>(ipsec_param.downlink_key().data());
  const auto key_size = ipsec_param.downlink_key().size();
  if (key_size != kKeyLen) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has a downlink_key "
                  "with wrong size";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has a downlink_key with wrong "
        "size");
  }

  absl::MutexLock l(&mutex_);
  aead_ctx_ = bssl::UniquePtr<EVP_AEAD_CTX>(EVP_AEAD_CTX_new(
      EVP_aead_aes_256_gcm(), key, key_size, sizeof(EspTrailer)));
  if (aead_ctx_ == nullptr) {
    LOG(ERROR) << "EVP_AEAD_CTX_new failure: keysize=" << key_size;
    return GetOpenSSLError("EVP_AEAD_CTX_new failure");
  }
  if (ipsec_param.downlink_salt().size() != kSaltLen) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has a downlink_salt "
                  "with wrong size";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has a downlink_salt with wrong "
        "size");
  }
  salt_ = ipsec_param.downlink_salt();

  return absl::OkStatus();
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
