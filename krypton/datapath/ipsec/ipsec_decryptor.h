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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_

#include <memory>
#include <string>
#include <utility>

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_packet_pool.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/aead.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

class IpSecDecryptor {
 public:
  IpSecDecryptor(EVP_AEAD_CTX* aead_ctx, absl::string_view salt)
      : aead_ctx_(aead_ctx), salt_(salt) {}

  static absl::StatusOr<std::unique_ptr<IpSecDecryptor>> Create(
      const TransformParams& params);

  absl::Status Decrypt(absl::string_view input, IpSecPacket* output,
                       IPProtocol* protocol);

  absl::Status Decrypt(absl::string_view input, uint8_t* output,
                       size_t max_output_size, size_t* actual_output_size,
                       IPProtocol* output_protocol);

 private:
  bssl::UniquePtr<EVP_AEAD_CTX> aead_ctx_;
  std::optional<std::string> salt_;
};

class Decryptor : public datapath::CryptorInterface {
 public:
  explicit Decryptor(std::unique_ptr<IpSecDecryptor> decryptor)
      : decryptor_(std::move(decryptor)) {}
  ~Decryptor() override = default;

  static absl::StatusOr<std::unique_ptr<Decryptor>> Create(
      const TransformParams& params);

  absl::StatusOr<Packet> Process(const Packet& packet) override;

 private:
  std::unique_ptr<IpSecDecryptor> decryptor_;
  IpSecPacketPool packet_pool_;
};

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_
