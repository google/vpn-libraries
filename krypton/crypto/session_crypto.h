// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_CRYPTO_SESSION_CRYPTO_H_
#define PRIVACY_NET_KRYPTON_CRYPTO_SESSION_CRYPTO_H_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/tink/cc/keyset_handle.h"

namespace privacy {
namespace krypton {
namespace crypto {

// Crypto material that is needed for a session.  This class manages only one
// private key. Initializing this class will generate a (private,public) key
// pair. Private key pair cannot be changed for the lifecycle of this class.
// This is not thread safe.
class SessionCrypto {
 public:
  explicit SessionCrypto(const KryptonConfig& config);
  ~SessionCrypto() = default;

  struct KeyMaterial {
    std::string public_value;
    std::string nonce;
  };
  // Returns the local key material.
  KeyMaterial GetMyKeyMaterial() const;

  // Returns the public value.
  std::string public_value() const { return absl::Base64Escape(public_value_); }

  // Set the remote public value. Remote public & salt should be in base64.
  absl::Status SetRemoteKeyMaterial(absl::string_view remote_public_value,
                                    absl::string_view nonce);

  // Provides the parameters needed for packet transform params.
  absl::StatusOr<TransformParams> GetTransformParams();

  // Generate a signature based on a public value. Here is an example:
  // Crypto key 1 : Used in initiation
  // Crypto key 2 : Used in rekey
  // Crypto key 2 public value is signed by Cryto Key 1.
  // public value should be base64 encoded.
  absl::StatusOr<std::string> GenerateSignature(
      absl::string_view other_public_value);

  // Get the base64 RekeyVerificationKey. This is used by the server to verify
  // the next request.
  absl::StatusOr<std::string> GetRekeyVerificationKey() const;

  // Test Only: Get the shared secret.
  absl::StatusOr<std::string> SharedKeyBase64TestOnly() const;

  // Test Only: override the salt.
  void SetLocalNonceBase64TestOnly(absl::string_view client_nonce);
  void SetRemoteNonceBase64TestOnly(absl::string_view server_nonce);

  // Private key.
  std::string PrivateKeyTestOnly() const { return private_key_; }

  uint32_t downlink_spi() const { return downlink_spi_; }

  // Set the public key received in PublicKeyResponse. Parameter is PEM
  // RSA public key.
  absl::Status SetBlindingPublicKey(absl::string_view rsa_public);
  std::optional<std::string> GetZincBlindToken() const;
  std::optional<std::string> GetBrassUnblindedToken(
      absl::string_view zinc_blind_signature) const;
  const std::string& original_message() const { return original_message_; }

  std::optional<std::string> GetRekeySignature() const {
    return rekey_signature_;
  }

  void SetSignature(absl::string_view signature) {
    rekey_signature_ = std::optional<std::string>(signature);
  }

  std::optional<std::string> blind_signing_public_key_hash() const {
    if (blind_signing_public_key_hash_.empty()) {
      return std::nullopt;
    }
    return absl::Base64Escape(blind_signing_public_key_hash_);
  }

  BN_CTX* bn_ctx() { return bn_ctx_.get(); }

 private:
  absl::StatusOr<TransformParams> ComputeIpSecKeyMaterial();
  absl::StatusOr<TransformParams> ComputeBridgeKeyMaterial();
  // Shared key for the session. Returns failure if the |SetRemotePublicValue|
  // is not called successfully. Use |SharedKeyBase64| for Base64 encoded
  // value.
  absl::StatusOr<std::string> SharedKey() const;

  std::string local_nonce_;  // random local 16 bytes nonce.
  std::string remote_nonce_;
  std::string private_key_;
  std::string public_value_;
  std::string remote_public_value_;  // Remote's public value.
  uint32_t downlink_spi_;
  std::unique_ptr<::crypto::tink::KeysetHandle> key_handle_ = nullptr;
  bssl::UniquePtr<BN_CTX> bn_ctx_ = nullptr;
  std::unique_ptr<RsaFdhBlinder> blinder_ = nullptr;
  std::unique_ptr<RsaFdhVerifier> verifier_ = nullptr;
  std::string original_message_;
  std::optional<std::string> rekey_signature_;
  std::string blind_signing_public_key_hash_;

  KryptonConfig config_;  // not owned.
};
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_CRYPTO_SESSION_CRYPTO_H_
