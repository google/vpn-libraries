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

#include <string>

#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/openssl/curve25519.h"
#include "third_party/tink/cc/public_key_verify.h"

namespace privacy {
namespace krypton {
namespace crypto {

namespace {

using ::testing::EqualsProto;
using ::testing::HasSubstr;
using ::testing::status::StatusIs;

class SessionCryptoTest : public testing::Test {
 public:
  void SetUp() override {
    bridge_config_aes_128_.set_datapath_protocol(KryptonConfig::BRIDGE);
    bridge_config_aes_128_.set_cipher_suite_key_length(128);

    bridge_config_aes_256_.set_datapath_protocol(KryptonConfig::BRIDGE);
    bridge_config_aes_256_.set_cipher_suite_key_length(256);

    ipsec_config_.set_datapath_protocol(KryptonConfig::IPSEC);
  }
  KryptonConfig bridge_config_aes_128_;
  KryptonConfig bridge_config_aes_256_;
  KryptonConfig ipsec_config_;
};

TEST_F(SessionCryptoTest, TestInitialKeyGeneration) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  LOG(INFO) << "Private Key " << local_crypto.PrivateKeyTestOnly();

  EXPECT_EQ(X25519_PRIVATE_KEY_LEN, local_crypto.PrivateKeyTestOnly().length());

  auto local_keys = local_crypto.GetMyKeyMaterial();
  EXPECT_EQ(X25519_PUBLIC_VALUE_LEN, local_keys.public_value.length());
}

TEST_F(SessionCryptoTest, TestSharedKeyBeforeSettingPublicValue) {
  SessionCrypto local_crypto(bridge_config_aes_128_);

  EXPECT_THAT(local_crypto.SharedKeyBase64TestOnly(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestSharedKey) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));
  EXPECT_EQ(local_crypto.SharedKeyBase64TestOnly(),
            remote_crypto.SharedKeyBase64TestOnly());
}

TEST_F(SessionCryptoTest, TestSettingInvalidRemotePublicValue) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();

  // Remove one character to make the public value invalid
  remote_keys.public_value = remote_keys.public_value.substr(1);

  EXPECT_THAT(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                                remote_keys.nonce),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("PublicValue")));
}

TEST_F(SessionCryptoTest, TestSettingInvalidRemoteNonce) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();

  // Remove one character to make the public value invalid
  remote_keys.nonce = remote_keys.nonce.substr(1);

  EXPECT_THAT(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                                remote_keys.nonce),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("Nonce")));
}

TEST_F(SessionCryptoTest, TestIpSecTransformFailure) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);
  EXPECT_THAT(local_crypto.GetTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestIpSecTransformParams) {
  SessionCrypto local_crypto(ipsec_config_);
  SessionCrypto remote_crypto(ipsec_config_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceTestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceTestOnly(local_keys.nonce);

  ASSERT_OK_AND_ASSIGN(auto transform_params,
                       local_crypto.GetTransformParams());
  auto local_ipsec_params = transform_params.ipsec();

  EXPECT_EQ(32, local_ipsec_params.downlink_key().length());
  EXPECT_EQ(32, local_ipsec_params.uplink_key().length());
  EXPECT_EQ(4, local_ipsec_params.uplink_salt().length());
  EXPECT_EQ(4l, local_ipsec_params.downlink_salt().length());

  ASSERT_OK_AND_ASSIGN(auto remote_transform_params,
                       remote_crypto.GetTransformParams());
  auto remote_ipsec_params = remote_transform_params.ipsec();

  // SessionCrypto creates a random downlink_spi every time it runs, so we need
  // to clear them before comparing two SessionCryptos.
  remote_ipsec_params.clear_downlink_spi();
  local_ipsec_params.clear_downlink_spi();

  EXPECT_THAT(remote_ipsec_params, EqualsProto(local_ipsec_params));
}

TEST_F(SessionCryptoTest, TestBridgeTransformFailure) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);
  EXPECT_THAT(local_crypto.GetTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestBridgeTransformParams128) {
  SessionCrypto local_crypto(bridge_config_aes_128_);
  SessionCrypto remote_crypto(bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceTestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceTestOnly(local_keys.nonce);

  ASSERT_OK_AND_ASSIGN(auto transform_params,
                       local_crypto.GetTransformParams());
  const auto& local_bridge_params = transform_params.bridge();

  EXPECT_EQ(16, local_bridge_params.downlink_key().length());
  EXPECT_EQ(16, local_bridge_params.uplink_key().length());

  EXPECT_THAT(remote_crypto.GetTransformParams()->bridge(),
              EqualsProto(local_bridge_params));

  // Duplicate call to GetTransform and ensure the keys are the same.
  ASSERT_OK_AND_ASSIGN(auto transform_params_1,
                       local_crypto.GetTransformParams());
  EXPECT_THAT(remote_crypto.GetTransformParams()->bridge(),
              EqualsProto(transform_params_1.bridge()));
}

TEST_F(SessionCryptoTest, TestBridgeTransformParams256) {
  SessionCrypto local_crypto(bridge_config_aes_256_);
  SessionCrypto remote_crypto(bridge_config_aes_256_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceTestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceTestOnly(local_keys.nonce);

  ASSERT_OK_AND_ASSIGN(auto transform_params,
                       local_crypto.GetTransformParams());

  ASSERT_TRUE(transform_params.has_bridge());
  const auto& local_bridge_params = transform_params.bridge();

  EXPECT_EQ(32, local_bridge_params.downlink_key().length());
  EXPECT_EQ(32, local_bridge_params.uplink_key().length());

  EXPECT_THAT(remote_crypto.GetTransformParams()->bridge(),
              EqualsProto(local_bridge_params));
}

TEST_F(SessionCryptoTest, VerifyRekey) {
  // Here the steps to verify rekey.
  // Step 1: Two session crypto keys previous (one exchanged earlier) and the
  // current one.
  // Step 2: Generate a signature based on current crypto public value and old
  // verification key.
  // Step 3: Validate the current public value signature matches.
  SessionCrypto previous(bridge_config_aes_128_);
  SessionCrypto current(bridge_config_aes_128_);

  ASSERT_OK_AND_ASSIGN(auto verification_key,
                       previous.GetRekeyVerificationKey());

  // Use previous ed25519 to generate a signature using the current public
  // value.
  ASSERT_OK_AND_ASSIGN(
      auto signature,
      previous.GenerateSignature(current.GetMyKeyMaterial().public_value));

  // Step 3: Time for validation.
  // Validate the signature by getting the keyset_handle from the previous
  // rekey_verification_key
  // Sigature check.
  ASSERT_OK_AND_ASSIGN(
      const auto handle,
      ::crypto::tink::KeysetHandle::ReadNoSecret(verification_key));
  ASSERT_OK_AND_ASSIGN(const auto verifier,
                       handle->GetPrimitive<::crypto::tink::PublicKeyVerify>());
  EXPECT_OK(
      verifier->Verify(signature, current.GetMyKeyMaterial().public_value));
}

TEST_F(SessionCryptoTest, VerifySignature) {
  SessionCrypto crypto(bridge_config_aes_128_);
  std::string data = "foo";

  ASSERT_OK_AND_ASSIGN(auto verification_key, crypto.GetRekeyVerificationKey());
  ASSERT_OK_AND_ASSIGN(auto signature, crypto.GenerateSignature(data));
  ASSERT_OK_AND_ASSIGN(
      const auto handle,
      ::crypto::tink::KeysetHandle::ReadNoSecret(verification_key));
  ASSERT_OK_AND_ASSIGN(const auto verifier,
                       handle->GetPrimitive<::crypto::tink::PublicKeyVerify>());
  EXPECT_OK(verifier->Verify(signature, data));
}

}  // namespace
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
