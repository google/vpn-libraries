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
#include <optional>
#include <string>

#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
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
  std::string public_value() const { return public_value_; }

  // Set the remote public value. Remote public & salt should be in base64.
  absl::Status SetRemoteKeyMaterial(absl::string_view remote_public_value,
                                    absl::string_view nonce);

  // Provides the parameters needed for packet transform params.
  absl::StatusOr<TransformParams> GetTransformParams();

  // Generate a signature based on a string of data. The data being signed
  // should not be base64 encoded. The returned value will not be base 64
  // encoded.
  absl::StatusOr<std::string> GenerateSignature(absl::string_view data);

  // Get the RekeyVerificationKey. This is used by the server to verify the next
  // request.
  absl::StatusOr<std::string> GetRekeyVerificationKey() const;

  // Test Only: Get the shared secret.
  absl::StatusOr<std::string> SharedKeyBase64TestOnly() const;

  // Test Only: override the salt.
  void SetLocalNonceTestOnly(absl::string_view client_nonce);
  void SetRemoteNonceTestOnly(absl::string_view server_nonce);

  // Private key.
  std::string PrivateKeyTestOnly() const { return private_key_; }

  uint32_t downlink_spi() const { return downlink_spi_; }

  std::optional<std::string> GetRekeySignature() const {
    return rekey_signature_;
  }

  void SetSignature(absl::string_view signature) {
    rekey_signature_ = std::optional<std::string>(signature);
  }

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
  std::optional<std::string> rekey_signature_;

  KryptonConfig config_;  // not owned.
};
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_CRYPTO_SESSION_CRYPTO_H_
