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

#include "privacy/net/krypton/crypto/session_crypto.h"

#include <algorithm>
#include <cstdint>
#include <tuple>

#include "base/logging.h"
#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/random/distributions.h"
#include "third_party/absl/random/random.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_join.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/curve25519.h"
#include "third_party/openssl/digest.h"
#include "third_party/openssl/rand.h"
#include "third_party/tink/cc/binary_keyset_writer.h"
#include "third_party/tink/cc/keyset_handle.h"
#include "third_party/tink/cc/public_key_sign.h"
#include "third_party/tink/cc/signature/signature_config.h"
#include "third_party/tink/cc/signature/signature_key_templates.h"
#include "third_party/tink/cc/subtle/common_enums.h"
#include "third_party/tink/cc/subtle/hkdf.h"
#include "third_party/tink/cc/subtle/pem_parser_boringssl.h"
#include "third_party/tink/cc/subtle/subtle_util_boringssl.h"
#include "third_party/tink/cc/util/secret_data.h"

namespace privacy {
namespace krypton {
namespace crypto {
namespace {
constexpr int kNonceLength = 16;
constexpr char kInfo[] = "Google PPN";

constexpr int kUplinkKeyPosition = 0;
constexpr int kUplinkKeySize = 32;
constexpr int kDownlinkKeyPosition = kUplinkKeyPosition + kUplinkKeySize;
constexpr int kDownlinkKeySize = 32;
constexpr int kUplinkSaltPosition = kDownlinkKeyPosition + kDownlinkKeySize;
constexpr int kUplinkSaltSize = 4;
constexpr int kDownlinkSaltPosition = kUplinkSaltPosition + kUplinkSaltSize;
constexpr int kDownlinkSaltSize = 4;
constexpr int kHkdfLength = kDownlinkSaltPosition + kDownlinkSaltSize;

constexpr int kBridgeUplinkKeyPosition = 0;
constexpr int kAes128KeySize = 16;
constexpr int kAes256KeySize = 32;
constexpr char kAlphabet[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

absl::StatusOr<std::string> SerializePublicKeyset(
    const ::crypto::tink::KeysetHandle &keyset_handle) {
  // Create a keyset writer with string_buf as output
  std::stringbuf string_buf;
  PPN_ASSIGN_OR_RETURN(auto keyset_writer_result,
                       ::crypto::tink::BinaryKeysetWriter::New(
                           absl::make_unique<std::ostream>(&string_buf)));

  // We only seriaze the public value of the keyset.
  PPN_ASSIGN_OR_RETURN(auto public_key, keyset_handle.GetPublicKeysetHandle());
  PPN_RETURN_IF_ERROR(public_key->WriteNoSecret(keyset_writer_result.get()));
  return string_buf.str();
}

std::string RandomUTF8String(size_t len, absl::string_view alphabet) {
  absl::BitGen gen;
  std::string result(len, '\0');
  const int k = alphabet.size();
  for (char &c : result) {
    c = alphabet[absl::Uniform<int>(gen, 0, k - 1)];
  }
  // Add a structure, for more context
  return absl::StrCat("blind:", result);
}

}  // namespace

SessionCrypto::SessionCrypto() : bn_ctx_(BN_CTX_new()) {
  DCHECK_NE(bn_ctx_.get(), nullptr);
  uint8_t private_key[X25519_PRIVATE_KEY_LEN];
  uint8_t public_value[X25519_PUBLIC_VALUE_LEN];

  // Generate the key pair
  X25519_keypair(public_value, private_key);
  private_key_ = std::string(reinterpret_cast<const char *>(private_key),
                             X25519_PRIVATE_KEY_LEN);
  public_value_ = std::string(reinterpret_cast<const char *>(public_value),
                              X25519_PUBLIC_VALUE_LEN);

  absl::BitGen gen;

  uint8_t rand_bytes[kNonceLength];
  if (RAND_bytes(rand_bytes, kNonceLength) != 1) {
    LOG(ERROR) << "Error generating Salt random bytes";
  }
  local_nonce_ =
      std::string(reinterpret_cast<const char *>(rand_bytes), kNonceLength);

  downlink_spi_ = absl::Uniform<uint32>(gen, 1, UINT32_MAX);

  // Generate another random 32 byte string that is used as blind message.
  original_message_ = RandomUTF8String(32, kAlphabet);

  if (!::crypto::tink::SignatureConfig::Register().ok()) {
    LOG(ERROR) << "Error registering with signature config";
    return;
  }

  auto status_or_key_handle = ::crypto::tink::KeysetHandle::GenerateNew(
      ::crypto::tink::SignatureKeyTemplates::Ed25519());
  if (!status_or_key_handle.ok()) {
    LOG(ERROR) << "Error generating Ed25519 key handle"
               << status_or_key_handle.status();
    return;
  }
  key_handle_ = std::move(status_or_key_handle.ValueOrDie());
}

void SessionCrypto::SetLocalNonceBase64TestOnly(
    absl::string_view client_nonce) {
  absl::Base64Unescape(client_nonce, &local_nonce_);
}

void SessionCrypto::SetRemoteNonceBase64TestOnly(
    absl::string_view server_nonce) {
  absl::Base64Unescape(server_nonce, &remote_nonce_);
}

absl::StatusOr<std::string> SessionCrypto::GetRekeyVerificationKey() const {
  PPN_ASSIGN_OR_RETURN(auto rekey_verification_key,
                       SerializePublicKeyset(*key_handle_));
  return absl::Base64Escape(rekey_verification_key);
}

absl::StatusOr<std::string> SessionCrypto::GenerateSignature(
    absl::string_view other_public_value) {
  std::string other_public_value_unescaped;
  absl::Base64Unescape(other_public_value, &other_public_value_unescaped);

  PPN_ASSIGN_OR_RETURN(
      auto public_sign_primitive,
      key_handle_->GetPrimitive<::crypto::tink::PublicKeySign>());
  PPN_ASSIGN_OR_RETURN(
      auto signed_public_value,
      public_sign_primitive->Sign(other_public_value_unescaped));
  return absl::Base64Escape(signed_public_value);
}

absl::StatusOr<std::string> SessionCrypto::SharedKey() const {
  if (remote_public_value_.empty()) {
    return absl::FailedPreconditionError("No remote public key set");
  }

  uint8_t shared_key[X25519_SHARED_KEY_LEN];
  // X25519 returns 1 or 0, 1 indicating success, 0 indicating failure.
  auto shared_key_result =
      X25519(shared_key, reinterpret_cast<const uint8_t *>(private_key_.data()),
             reinterpret_cast<const uint8_t *>(remote_public_value_.data()));
  if (shared_key_result != 1) {
    return absl::InternalError("Shared key generation failed");
  }

  return std::string(reinterpret_cast<const char *>(shared_key),
                     X25519_SHARED_KEY_LEN);
}

absl::StatusOr<std::string> SessionCrypto::SharedKeyBase64TestOnly() const {
  PPN_ASSIGN_OR_RETURN(auto shared_key, SharedKey());
  return absl::Base64Escape(shared_key);
}

absl::Status SessionCrypto::SetRemoteKeyMaterial(
    const std::string &remote_public_value, const std::string &remote_nonce) {
  if (ip_sec_transform_params_) {
    return absl::AlreadyExistsError("IpSec parameters are already generated");
  }

  std::string remote_public;
  if (!absl::Base64Unescape(remote_public_value, &remote_public)) {
    return absl::FailedPreconditionError(
        "Base64 unescape failed, Remote public should be in base64");
  }

  if (remote_public.length() != X25519_PUBLIC_VALUE_LEN) {
    return absl::FailedPreconditionError(
        absl::StrCat("PublicValue length should be 32 bytes, received ",
                     remote_public.length()));
  }

  remote_public_value_ = remote_public;

  std::string nonce;
  if (!absl::Base64Unescape(remote_nonce, &nonce)) {
    return absl::FailedPreconditionError(
        "Base64 unescape failed, remote nonce should be in base 64");
  }

  if (nonce.length() != kNonceLength) {
    return absl::FailedPreconditionError("Nonce should be 16 bytes");
  }
  remote_nonce_ = nonce;
  return absl::OkStatus();
}

absl::Status SessionCrypto::ComputeIpSecKeyMaterial() {
  PPN_ASSIGN_OR_RETURN(auto shared_key, SharedKey());

  PPN_ASSIGN_OR_RETURN(
      auto hkdf_secret_data,
      ::crypto::tink::subtle::Hkdf::ComputeHkdf(
          ::crypto::tink::subtle::SHA256,
          ::crypto::tink::util::SecretDataFromStringView(shared_key),
          absl::StrCat(local_nonce_, remote_nonce_), kInfo, kHkdfLength));

  auto hkdf_string =
      ::crypto::tink::util::SecretDataAsStringView(hkdf_secret_data);

  DCHECK_EQ(hkdf_string.size(), kHkdfLength);
  // Key placements in the HKDF output of 72 bytes.
  //+--------------------------------------------------------------------+
  //|                        |                       |Uplink   |Downlink |
  //| Uplink Key(32)         |Downlink Key (32)      |Salt(4)  |Salt(4)  |
  //+--------------------------------------------------------------------+
  ip_sec_transform_params_ = IpSecTransformParams();
  ip_sec_transform_params_->set_uplink_key(
      hkdf_string.substr(kUplinkKeyPosition, kUplinkKeySize));
  ip_sec_transform_params_->set_downlink_key(
      hkdf_string.substr(kDownlinkKeyPosition, kDownlinkKeySize));
  ip_sec_transform_params_->set_uplink_salt(
      hkdf_string.substr(kUplinkSaltPosition, kUplinkSaltSize));
  ip_sec_transform_params_->set_downlink_salt(
      hkdf_string.substr(kDownlinkSaltPosition, kDownlinkSaltSize));

  return absl::OkStatus();
}

absl::StatusOr<IpSecTransformParams> SessionCrypto::GetIpSecTransformParams() {
  if (!ip_sec_transform_params_) {
    PPN_RETURN_IF_ERROR(ComputeIpSecKeyMaterial());
  }
  return ip_sec_transform_params_.value();
}

SessionCrypto::KeyMaterial SessionCrypto::GetMyKeyMaterial() const {
  SessionCrypto::KeyMaterial keys;
  keys.public_value = absl::Base64Escape(public_value_);
  keys.nonce = absl::Base64Escape(local_nonce_);
  return keys;
}

absl::Status SessionCrypto::ComputeBridgeKeyMaterial(CryptoSuite suite) {
  int key_length = 0;
  // Length of the hkdf length.
  int hkdf_length = 0;
  switch (suite) {
    case CryptoSuite::AES128_GCM:
      key_length = kAes128KeySize;
      hkdf_length = key_length * 2;
      break;
    case CryptoSuite::AES256_GCM:
      key_length = kAes256KeySize;
      hkdf_length = key_length * 2;
      break;
    default:
      return absl::InvalidArgumentError("Unspecified key length");
  }

  PPN_ASSIGN_OR_RETURN(auto shared_key, SharedKey());

  PPN_ASSIGN_OR_RETURN(
      auto hkdf_secret_data,
      ::crypto::tink::subtle::Hkdf::ComputeHkdf(
          ::crypto::tink::subtle::SHA256,
          ::crypto::tink::util::SecretDataFromStringView(shared_key),
          absl::StrCat(local_nonce_, remote_nonce_), kInfo, hkdf_length));

  auto hkdf_string =
      ::crypto::tink::util::SecretDataAsStringView(hkdf_secret_data);

  // Key placements in the HKDF output of 32 or 64 bytes.
  //+---------------------------------------------------+
  //|                           |                       |
  //| Uplink Key(16/32)         |Downlink Key (16/32)   |
  //+---------------------------------------------------+
  bridge_transform_params_ = BridgeTransformParams();
  bridge_transform_params_->set_uplink_key(
      hkdf_string.substr(kBridgeUplinkKeyPosition, key_length));
  bridge_transform_params_->set_downlink_key(
      hkdf_string.substr(kBridgeUplinkKeyPosition + key_length, key_length));

  return absl::OkStatus();
}
absl::StatusOr<BridgeTransformParams> SessionCrypto::GetBridgeTransformParams(
    CryptoSuite suite) {
  if (!bridge_transform_params_) {
    PPN_RETURN_IF_ERROR(ComputeBridgeKeyMaterial(suite));
  }
  return bridge_transform_params_.value();
}

absl::Status SessionCrypto::SetBlindingPublicKey(absl::string_view rsa_public) {
  PPN_ASSIGN_OR_RETURN(
      const auto subtle_rsa_public_key,
      ::crypto::tink::subtle::PemParser::ParseRsaPublicKey(rsa_public));

  if (subtle_rsa_public_key == nullptr) {
    LOG(ERROR) << "RSA public key is null";
    return absl::FailedPreconditionError("RSA public key is null");
  }

  PPN_ASSIGN_OR_RETURN(
      auto bssl_unique_rsa,
      ::crypto::tink::subtle::SubtleUtilBoringSSL::BoringSslRsaFromRsaPublicKey(
          *subtle_rsa_public_key));

  if (bssl_unique_rsa == nullptr) {
    return absl::FailedPreconditionError("bssl_unique_rsa public key is null");
  }

  // Create the verifier.
  PPN_ASSIGN_OR_RETURN(verifier_, RsaFdhVerifier::New(*subtle_rsa_public_key));

  // Create the blinder.
  PPN_ASSIGN_OR_RETURN(
      blinder_,
      RsaFdhBlinder::Blind(original_message(), std::move(bssl_unique_rsa),
                           bn_ctx_.get()));

  PPN_ASSIGN_OR_RETURN(
      auto hash, ::crypto::tink::subtle::boringssl::ComputeHash(rsa_public,
                                                                *EVP_sha256()));
  blind_signing_public_key_hash_ = std::string(hash.begin(), hash.end());

  return absl::OkStatus();
}

absl::optional<std::string> SessionCrypto::GetZincBlindToken() const {
  if (blinder_ == nullptr) {
    return absl::nullopt;
  }
  return absl::Base64Escape(blinder_->blind());
}

absl::optional<std::string> SessionCrypto::GetBrassUnblindedToken(
    absl::string_view zinc_blind_signature) const {
  if (blinder_ == nullptr) {
    return absl::nullopt;
  }
  auto status_or_unblind_signature =
      blinder_->Unblind(zinc_blind_signature, bn_ctx_.get());
  if (!status_or_unblind_signature.ok()) {
    return absl::nullopt;
  }
  return absl::Base64Escape(status_or_unblind_signature.value());
}


}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
