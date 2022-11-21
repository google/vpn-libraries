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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_ENCRYPTOR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_ENCRYPTOR_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_packet_pool.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/aead.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

class IpSecEncryptor {
 public:
  IpSecEncryptor(EVP_AEAD_CTX* aead_ctx, absl::string_view salt, uint32_t spi)
      : aead_ctx_(aead_ctx), salt_(salt), spi_(spi), sequence_number_(0) {}

  static absl::StatusOr<std::unique_ptr<IpSecEncryptor>> Create(
      uint32_t spi, const TransformParams& params);

  absl::Status Encrypt(absl::string_view input, IPProtocol protocol,
                       IpSecPacket* output);

 private:
  bssl::UniquePtr<EVP_AEAD_CTX> aead_ctx_;
  std::optional<std::string> salt_;
  uint32_t spi_;
  std::atomic_uint32_t sequence_number_;
};

class Encryptor : public datapath::CryptorInterface {
 public:
  explicit Encryptor(std::unique_ptr<IpSecEncryptor> encryptor)
      : encryptor_(std::move(encryptor)) {}
  ~Encryptor() override = default;

  static absl::StatusOr<std::unique_ptr<Encryptor>> Create(
      uint32_t spi, const TransformParams& params);

  absl::StatusOr<Packet> Process(const Packet& packet) override;

 private:
  std::unique_ptr<IpSecEncryptor> encryptor_;
  IpSecPacketPool packet_pool_;
};

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_ENCRYPTOR_H_
