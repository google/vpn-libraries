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

#ifndef PRIVACY_NET_KRYPTON_CRYPTO_RSA_FDH_BLINDER_H_
#define PRIVACY_NET_KRYPTON_CRYPTO_RSA_FDH_BLINDER_H_

#include <memory>
#include <string_view>
#include <vector>

#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/rsa.h"
#include "third_party/tink/cc/subtle/subtle_util_boringssl.h"

namespace privacy {
namespace krypton {
namespace crypto {

// RsaFdhBlinder represents a blinded value (probably an FDH hash), ready for
// signing.  It can also unblind a blinded value assuming it was signed by the
// matching key used in the initialization call to `Blind`.
class RsaFdhBlinder {
 public:
  ~RsaFdhBlinder() = default;

  // Blind `message` using n and e derived from an RSA public key.
  // `message` will first be hashed with a Shake256 Full Domain Hash of the
  // message. This hash matches that used by RsaVerifier.
  static absl::StatusOr<std::unique_ptr<RsaFdhBlinder>> Blind(
      const absl::string_view message, bssl::UniquePtr<RSA> signer_public_key,
      BN_CTX* bn_ctx);

  const absl::string_view blind() const { return blind_; }

  // Unblinds `blind_signature`.
  absl::StatusOr<std::string> Unblind(const absl::string_view blind_signature,
                                      BN_CTX* bn_ctx) const;

 private:
  // Use `Blind` to construct
  RsaFdhBlinder(bssl::UniquePtr<BIGNUM> r, bssl::UniquePtr<RSA> public_key,
                std::string blind);

  const bssl::UniquePtr<BIGNUM> r_;
  bssl::UniquePtr<RSA> public_key_;
  std::string blind_;
};

// RsaFdhBlindSigner signs a set of blinded data with the given key, resulting
// in an unblindable signature.
class RsaFdhBlindSigner {
 public:
  ~RsaFdhBlindSigner() = default;

  static absl::StatusOr<std::unique_ptr<RsaFdhBlindSigner>> New(
      const ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey&
          private_key);

  absl::StatusOr<std::string> Sign(const absl::string_view blinded_data) const;

 private:
  // Use New to construct.
  explicit RsaFdhBlindSigner(bssl::UniquePtr<RSA> signing_key)
      : signing_key_(std::move(signing_key)) {}

  const bssl::UniquePtr<RSA> signing_key_;
};

// RsaFdhVerifier verifies a hash matches a signature with a given public key.
class RsaFdhVerifier {
 public:
  ~RsaFdhVerifier() = default;

  static absl::StatusOr<std::unique_ptr<RsaFdhVerifier>> New(
      const ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey&
          public_key);

  absl::Status Verify(const absl::string_view message,
                      const absl::string_view signature, BN_CTX* bn_ctx) const;

 private:
  // Use New to construct.
  explicit RsaFdhVerifier(bssl::UniquePtr<RSA> verification_key)
      : verification_key_(std::move(verification_key)) {}

  const bssl::UniquePtr<RSA> verification_key_;
};

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_CRYPTO_RSA_FDH_BLINDER_H_
