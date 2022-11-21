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

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"

#include "privacy/net/krypton/utils/status.h"

#ifdef _WIN32
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
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

/* static */ absl::StatusOr<std::unique_ptr<IpSecDecryptor>>
IpSecDecryptor::Create(const TransformParams& params) {
  if (!params.has_ipsec()) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams is null";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams is null");
  }
  const auto& ipsec_param = params.ipsec();

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

  EVP_AEAD_CTX* aead_ctx =
      EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), key, key_size, kEspTagLen);
  if (aead_ctx == nullptr) {
    LOG(ERROR) << "EVP_AEAD_CTX_new failure: keysize=" << key_size;
    return crypto::GetOpenSSLError("EVP_AEAD_CTX_new failure");
  }
  if (ipsec_param.downlink_salt().size() != kSaltLen) {
    LOG(ERROR) << "TransformParams.IpSecTransformParams has a downlink_salt "
                  "with wrong size";
    return absl::InvalidArgumentError(
        "TransformParams.IpSecTransformParams has a downlink_salt with wrong "
        "size");
  }
  std::string salt = ipsec_param.downlink_salt();

  return std::make_unique<IpSecDecryptor>(aead_ctx, salt);
}

absl::Status IpSecDecryptor::Decrypt(absl::string_view input,
                                     IpSecPacket* output,
                                     IPProtocol* protocol) {
  size_t actual_output_size = 0;
  PPN_RETURN_IF_ERROR(Decrypt(input, reinterpret_cast<uint8_t*>(output->data()),
                              output->max_data_size(), &actual_output_size,
                              protocol));
  output->resize_data(actual_output_size);
  return absl::OkStatus();
}

absl::Status IpSecDecryptor::Decrypt(absl::string_view input, uint8_t* output,
                                     size_t max_output_size,
                                     size_t* actual_output_size,
                                     IPProtocol* output_protocol) {
  if (input.size() <= sizeof(EspHeader)) {
    LOG(ERROR) << "Packet size is too small: " << input.size();
    return absl::InvalidArgumentError("Packet size is too small");
  }

  const auto ciphertext_length = input.size() - sizeof(EspHeader);
  const auto plaintext_length = ciphertext_length;
  if (ciphertext_length > max_output_size) {
    LOG(ERROR) << "Packet size is too large: " << input.size();
    return absl::InvalidArgumentError("Packet size is too large");
  }
  auto input_header =
      const_cast<EspHeader*>(reinterpret_cast<const EspHeader*>(input.data()));
  auto input_data = reinterpret_cast<uint8_t*>(const_cast<char*>(input.data()) +
                                               sizeof(EspHeader));

  if (output == nullptr) {
    LOG(ERROR) << "output data buffer is null";
    return absl::InvalidArgumentError("output data buffer is null");
  }

  // Encryptors are responsible for ensuring these numbers are big-endian.
  auto spi = input_header->client_spi;
  auto sequence_number = input_header->sequence_number;
  CHECK_EQ(sizeof(input_header->initialization_vector), kIVLen);
  char aad[sizeof(spi) + sizeof(sequence_number)];
  memcpy(aad, &spi, sizeof(spi));
  memcpy(aad + sizeof(spi), &sequence_number, sizeof(sequence_number));
  const auto aad_head = reinterpret_cast<const uint8_t*>(aad);

  char nonce[kSaltLen + kIVLen];
  memcpy(nonce, salt_->c_str(), kSaltLen);
  memcpy(nonce + kSaltLen, &(input_header->initialization_vector), kIVLen);

  size_t dst_len;
  if (EVP_AEAD_CTX_open(aead_ctx_.get(), output, &dst_len, ciphertext_length,
                        reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce),
                        input_data, plaintext_length, aad_head,
                        sizeof(spi) + sizeof(sequence_number)) != 1) {
    LOG(ERROR) << "EVP_AEAD_CTX_open failed";
    return crypto::GetOpenSSLError("EVP_AEAD_CTX_open failed");
  }

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
  auto pad_len_ptr = output + dst_len - 2;
  const int pad_len = *pad_len_ptr;

  // Verify the next header is populated correctly.
  auto next_header = *(output + dst_len - 1);
  *output_protocol = IPProtocol::kUnknown;
  if (next_header == IPPROTO_IPIP) {
    *output_protocol = IPProtocol::kIPv4;
  } else if (next_header == IPPROTO_IPV6) {
    *output_protocol = IPProtocol::kIPv6;
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("Unsupported protocol: ", next_header));
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

  *actual_output_size = dst_len - pad_len - 2;

  return absl::OkStatus();
}

absl::StatusOr<Packet> Decryptor::Process(const Packet& packet) {
  auto output = packet_pool_.Borrow();
  if (!output) {
    LOG(INFO) << "Dropping a downlink packet.";
    return absl::ResourceExhaustedError("packet pool is exhausted");
  }

  IPProtocol ip_protocol;
  PPN_RETURN_IF_ERROR(
      decryptor_->Decrypt(packet.data(), output.get(), &ip_protocol));

  // The pool won't be destroyed until all packets have been returned, so it's
  // safe to capture a pointer to it here.
  return Packet(output->data(), output->data_size(), ip_protocol, [output] {});
}

/* static */ absl::StatusOr<std::unique_ptr<Decryptor>> Decryptor::Create(
    const TransformParams& params) {
  PPN_ASSIGN_OR_RETURN(auto decryptor, IpSecDecryptor::Create(params));
  return std::make_unique<Decryptor>(std::move(decryptor));
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
