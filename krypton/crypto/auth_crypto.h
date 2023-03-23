// Copyright 2023 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_CRYPTO_AUTH_CRYPTO_H_
#define PRIVACY_NET_KRYPTON_CRYPTO_AUTH_CRYPTO_H_

#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace crypto {

// Crypto material that is needed for a session.  This class manages only one
// private key. Initializing this class will generate a (private,public) key
// pair. Private key pair cannot be changed for the lifecycle of this class.
// This is not thread safe.
class AuthCrypto {
 public:
  explicit AuthCrypto(const KryptonConfig& config);
  ~AuthCrypto() = default;

  // Set the public key received in PublicKeyResponse. Parameter is PEM
  // RSA public key.
  absl::Status SetBlindingPublicKey(absl::string_view rsa_public);
  std::optional<std::string> GetZincBlindToken() const;
  std::optional<std::string> GetBrassUnblindedToken(
      absl::string_view zinc_blind_signature) const;
  const std::string& original_message() const { return original_message_; }

  std::optional<std::string> blind_signing_public_key_hash() const {
    if (blind_signing_public_key_hash_.empty()) {
      return std::nullopt;
    }
    return absl::Base64Escape(blind_signing_public_key_hash_);
  }

  BN_CTX* bn_ctx() { return bn_ctx_.get(); }

 private:
  bssl::UniquePtr<BN_CTX> bn_ctx_ = nullptr;
  std::unique_ptr<RsaFdhBlinder> blinder_ = nullptr;
  std::unique_ptr<RsaFdhVerifier> verifier_ = nullptr;
  std::string original_message_;
  std::string blind_signing_public_key_hash_;

  KryptonConfig config_;
};
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_CRYPTO_AUTH_CRYPTO_H_
