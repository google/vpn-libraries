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

#include "privacy/net/krypton/crypto/session_crypto.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/check.h"
#include "third_party/absl/log/log.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/curve25519.h"
#include "third_party/openssl/rand.h"
#include "third_party/tink/cc/binary_keyset_writer.h"
#include "third_party/tink/cc/keyset_handle.h"
#include "third_party/tink/cc/public_key_sign.h"
#include "third_party/tink/cc/signature/signature_config.h"
#include "third_party/tink/cc/signature/signature_key_templates.h"
#include "third_party/tink/cc/subtle/common_enums.h"
#include "third_party/tink/cc/subtle/hkdf.h"
#include "third_party/tink/cc/subtle/random.h"
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

absl::StatusOr<std::string> SerializePublicKeyset(
    const ::crypto::tink::KeysetHandle &keyset_handle) {
  // Create a keyset writer with string_buf as output
  std::stringbuf string_buf;
  PPN_ASSIGN_OR_RETURN(auto keyset_writer_result,
                       ::crypto::tink::BinaryKeysetWriter::New(
                           std::make_unique<std::ostream>(&string_buf)));

  // We only serialize the public value of the keyset.
  PPN_ASSIGN_OR_RETURN(auto public_key, keyset_handle.GetPublicKeysetHandle());
  PPN_RETURN_IF_ERROR(public_key->WriteNoSecret(keyset_writer_result.get()));
  return string_buf.str();
}

}  // namespace

absl::StatusOr<std::unique_ptr<SessionCrypto>> SessionCrypto::Create(
    const KryptonConfig &config) {
  auto session_crypto = absl::WrapUnique(new SessionCrypto(config));
  PPN_RETURN_IF_ERROR(session_crypto->Init());
  return session_crypto;
}

SessionCrypto::SessionCrypto(const KryptonConfig &config)
    : downlink_spi_(0), bn_ctx_(BN_CTX_new()), config_(config) {}

void SessionCrypto::SetLocalNonceTestOnly(absl::string_view client_nonce) {
  local_nonce_ = std::string(client_nonce);
}

void SessionCrypto::SetRemoteNonceTestOnly(absl::string_view server_nonce) {
  remote_nonce_ = std::string(server_nonce);
}

absl::StatusOr<std::string> SessionCrypto::GetRekeyVerificationKey() const {
  return SerializePublicKeyset(*key_handle_);
}

absl::StatusOr<std::string> SessionCrypto::GenerateSignature(
    absl::string_view data) {
  PPN_ASSIGN_OR_RETURN(
      auto public_sign_primitive,
      key_handle_->GetPrimitive<::crypto::tink::PublicKeySign>());
  return public_sign_primitive->Sign(data);
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
    absl::string_view remote_public_value, absl::string_view remote_nonce) {
  LOG(INFO) << "Remote key material received";

  if (remote_public_value.length() != X25519_PUBLIC_VALUE_LEN) {
    return absl::FailedPreconditionError(
        absl::StrCat("PublicValue length should be 32 bytes, received ",
                     remote_public_value.length()));
  }

  remote_public_value_ = std::string(remote_public_value);

  if (remote_nonce.length() != kNonceLength) {
    return absl::FailedPreconditionError("Nonce should be 16 bytes");
  }
  remote_nonce_ = std::string(remote_nonce);
  return absl::OkStatus();
}

absl::Status SessionCrypto::Init() {
  if (bn_ctx_.get() == nullptr) {
    return absl::FailedPreconditionError("bn_ctx_ is null");
  }
  uint8_t private_key[X25519_PRIVATE_KEY_LEN];
  uint8_t public_value[X25519_PUBLIC_VALUE_LEN];

  // Generate the key pair
  X25519_keypair(public_value, private_key);
  private_key_ = std::string(reinterpret_cast<const char *>(private_key),
                             X25519_PRIVATE_KEY_LEN);
  public_value_ = std::string(reinterpret_cast<const char *>(public_value),
                              X25519_PUBLIC_VALUE_LEN);

  uint8_t rand_bytes[kNonceLength];
  if (RAND_bytes(rand_bytes, kNonceLength) != 1) {
    LOG(ERROR) << "Error generating Salt random bytes";
  }
  local_nonce_ =
      std::string(reinterpret_cast<const char *>(rand_bytes), kNonceLength);

  downlink_spi_ = ::crypto::tink::subtle::Random::GetRandomUInt32();

  if (!::crypto::tink::SignatureConfig::Register().ok()) {
    return absl::InternalError("Error registering with signature config");
  }

  // NOTE: This is a crypto::tink::util::StatusOr, not an absl::StatusOr.
  auto key_handle = ::crypto::tink::KeysetHandle::GenerateNew(
      ::crypto::tink::SignatureKeyTemplates::Ed25519());
  if (!key_handle.ok()) {
    LOG(ERROR) << "Error generating Ed25519 key handle" << key_handle.status();
    return key_handle.status();
  }
  key_handle_ = *std::move(key_handle);
  return absl::OkStatus();
}

absl::StatusOr<TransformParams> SessionCrypto::ComputeIpSecKeyMaterial() {
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
  TransformParams transform_params;
  auto ip_sec_transform_params = transform_params.mutable_ipsec();
  ip_sec_transform_params->set_uplink_key(
      hkdf_string.substr(kUplinkKeyPosition, kUplinkKeySize));
  ip_sec_transform_params->set_downlink_key(
      hkdf_string.substr(kDownlinkKeyPosition, kDownlinkKeySize));
  ip_sec_transform_params->set_uplink_salt(
      hkdf_string.substr(kUplinkSaltPosition, kUplinkSaltSize));
  ip_sec_transform_params->set_downlink_salt(
      hkdf_string.substr(kDownlinkSaltPosition, kDownlinkSaltSize));

  ip_sec_transform_params->set_downlink_spi(downlink_spi());

  return transform_params;
}

SessionCrypto::KeyMaterial SessionCrypto::GetMyKeyMaterial() const {
  SessionCrypto::KeyMaterial keys;
  keys.public_value = public_value_;
  keys.nonce = local_nonce_;
  return keys;
}

absl::StatusOr<TransformParams> SessionCrypto::ComputeBridgeKeyMaterial() {
  LOG(INFO) << "Computing BridgeKeyMaterial";
  int key_length = 0;
  // Length of the hkdf length.
  int hkdf_length = 0;
  switch (config_.cipher_suite_key_length()) {
    case kAes128KeySize * 8:
      key_length = kAes128KeySize;
      hkdf_length = key_length * 2;
      break;
    case kAes256KeySize * 8:
      key_length = kAes256KeySize;
      hkdf_length = key_length * 2;
      break;
    default:
      return absl::InvalidArgumentError(absl::StrCat(
          "Unspecified key length:", config_.cipher_suite_key_length()));
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
  TransformParams transform_params;
  auto bridge_transform_params = transform_params.mutable_bridge();
  bridge_transform_params->set_uplink_key(
      hkdf_string.substr(kBridgeUplinkKeyPosition, key_length));
  bridge_transform_params->set_downlink_key(
      hkdf_string.substr(kBridgeUplinkKeyPosition + key_length, key_length));

  return transform_params;
}

absl::StatusOr<TransformParams> SessionCrypto::GetTransformParams() {
  switch (config_.datapath_protocol()) {
    case KryptonConfig::BRIDGE: {
      return ComputeBridgeKeyMaterial();
    } break;
    case KryptonConfig::IPSEC: {
      return ComputeIpSecKeyMaterial();
    } break;
    default: {
      return absl::InvalidArgumentError(
          "Invalid KryptonConfig for datapath protocol");
    }
  }
}

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
