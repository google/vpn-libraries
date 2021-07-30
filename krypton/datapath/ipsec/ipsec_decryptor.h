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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_

#include "privacy/net/krypton/datapath/cryptor_interface.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec.h"
#include "privacy/net/krypton/pal/packet.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/aead.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

class Decryptor : public datapath::CryptorInterface {
 public:
  Decryptor() = default;
  ~Decryptor() override = default;

  absl::Status Start(const TransformParams& params);

  absl::StatusOr<Packet> Process(const Packet& packet) override;
  absl::Status Rekey(const TransformParams& params) override;

 private:
  absl::Mutex mutex_;
  bssl::UniquePtr<EVP_AEAD_CTX> aead_ctx_ ABSL_GUARDED_BY(mutex_);
  absl::optional<std::string> salt_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_IPSEC_DECRYPTOR_H_
