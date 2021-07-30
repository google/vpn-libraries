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

#include "privacy/net/brass/rpc/brass.proto.h"
#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/types/optional.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/curve25519.h"
#include "third_party/tink/cc/public_key_verify.h"
#include "third_party/tink/cc/subtle/pem_parser_boringssl.h"

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
  SessionCrypto local_crypto(&bridge_config_aes_128_);
  SessionCrypto remote_crypto(&bridge_config_aes_128_);
  LOG(INFO) << "Private Key "
            << absl::Base64Escape(local_crypto.PrivateKeyTestOnly());

  EXPECT_EQ(X25519_PRIVATE_KEY_LEN, local_crypto.PrivateKeyTestOnly().length());

  auto key_material = local_crypto.GetMyKeyMaterial();
  std::string unescaped_public;
  auto local_keys = local_crypto.GetMyKeyMaterial();
  absl::Base64Unescape(local_keys.public_value, &unescaped_public);
  EXPECT_EQ(X25519_PUBLIC_VALUE_LEN, unescaped_public.length());
}

TEST_F(SessionCryptoTest, TestSharedKeyBeforeSettingPublicValue) {
  SessionCrypto local_crypto(&bridge_config_aes_128_);

  EXPECT_THAT(local_crypto.SharedKeyBase64TestOnly(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestSharedKey) {
  SessionCrypto local_crypto(&bridge_config_aes_128_);
  SessionCrypto remote_crypto(&bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));
  EXPECT_EQ(local_crypto.SharedKeyBase64TestOnly(),
            remote_crypto.SharedKeyBase64TestOnly());
}

TEST_F(SessionCryptoTest, TestIpSecTransformFailure) {
  SessionCrypto local_crypto(&bridge_config_aes_128_);
  SessionCrypto remote_crypto(&bridge_config_aes_128_);
  EXPECT_THAT(local_crypto.GetTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestIpSecTransformParams) {
  SessionCrypto local_crypto(&ipsec_config_);
  SessionCrypto remote_crypto(&ipsec_config_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceBase64TestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceBase64TestOnly(local_keys.nonce);

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               remote_keys.nonce));

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
  SessionCrypto local_crypto(&bridge_config_aes_128_);
  SessionCrypto remote_crypto(&bridge_config_aes_128_);
  EXPECT_THAT(local_crypto.GetTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SessionCryptoTest, TestBridgeTransformParams128) {
  SessionCrypto local_crypto(&bridge_config_aes_128_);
  SessionCrypto remote_crypto(&bridge_config_aes_128_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceBase64TestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceBase64TestOnly(local_keys.nonce);

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               remote_keys.nonce));

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
  SessionCrypto local_crypto(&bridge_config_aes_256_);
  SessionCrypto remote_crypto(&bridge_config_aes_256_);

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();
  // Set key material between two sessions, local & remote.

  // Inorder for the IpsecTransforms to be the same.  Reverse the salts so that
  // HKDF will use the same sequence of bytes.
  remote_crypto.SetRemoteNonceBase64TestOnly(remote_keys.nonce);
  remote_crypto.SetLocalNonceBase64TestOnly(local_keys.nonce);

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               remote_keys.nonce));

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
  SessionCrypto previous(&bridge_config_aes_128_);
  SessionCrypto current(&bridge_config_aes_128_);
  std::string verification_key;
  std::string signature;
  std::string current_public_value;

  absl::Base64Unescape(current.GetMyKeyMaterial().public_value,
                       &current_public_value);

  ASSERT_OK_AND_ASSIGN(auto escaped_verification_key,
                       previous.GetRekeyVerificationKey());
  absl::Base64Unescape(escaped_verification_key, &verification_key);

  // Use previous ed25519 to generate a signature using the current public
  // value.
  ASSERT_OK_AND_ASSIGN(
      auto escaped_signature,
      previous.GenerateSignature(current.GetMyKeyMaterial().public_value));
  absl::Base64Unescape(escaped_signature, &signature);

  // Step 3: Time for validation.
  // Validate the signature by getting the keyset_handle from the previous
  // rekey_verification_key
  // Sigature check.
  ASSERT_OK_AND_ASSIGN(
      const auto handle,
      ::crypto::tink::KeysetHandle::ReadNoSecret(verification_key));
  ASSERT_OK_AND_ASSIGN(const auto verifier,
                       handle->GetPrimitive<::crypto::tink::PublicKeyVerify>());
  EXPECT_OK(verifier->Verify(signature, current_public_value));
}

TEST_F(SessionCryptoTest, BlindingOk) {
  // Some random public string.
  std::string rsa_pem = absl::StrCat(
      "-----BEGIN PUBLIC KEY-----\n",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n",
      "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n",
      "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n",
      "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n",
      "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n",
      "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n",
      "wQIDAQAB\n", "-----END PUBLIC KEY-----\n");

  SessionCrypto crypto(&bridge_config_aes_128_);
  EXPECT_OK(crypto.SetBlindingPublicKey(rsa_pem));
  auto optional_blind = crypto.GetZincBlindToken();
  EXPECT_NE(optional_blind, absl::nullopt);
  EXPECT_NE(optional_blind.value().size(), 0);
  // This is the SHA256 of the hardcoded |rsa_pem| above.
  EXPECT_EQ(crypto.blind_signing_public_key_hash(),
            "aV07BUI5y+F8E/ESXXZRx8cKh0lT4J4VBDjlOl25850=");
}

TEST_F(SessionCryptoTest, BlindSignOk) {
  SessionCrypto crypto(&bridge_config_aes_128_);

  BN_CTX_start(crypto.bn_ctx());
  auto rsa_f4 = BN_CTX_get(crypto.bn_ctx());
  EXPECT_TRUE(BN_set_u64(rsa_f4, RSA_F4));

  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey private_key;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey public_key;
  EXPECT_THAT(::crypto::tink::subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
                  2048, rsa_f4, &private_key, &public_key),
              testing::status::IsOk());

  ASSERT_OK_AND_ASSIGN(
      const std::string pem,
      ::crypto::tink::subtle::PemParser::WriteRsaPublicKey(public_key));

  EXPECT_OK(crypto.SetBlindingPublicKey(pem));
  auto blind_opt = crypto.GetZincBlindToken();
  EXPECT_NE(blind_opt, absl::nullopt);

  std::string raw_blind;
  absl::Base64Unescape(blind_opt.value(), &raw_blind);

  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(private_key));
  ASSERT_OK_AND_ASSIGN(auto sig, signer->Sign(raw_blind));

  auto unblind_sig = crypto.GetBrassUnblindedToken(sig);
  ASSERT_NE(unblind_sig, absl::nullopt);

  ASSERT_OK_AND_ASSIGN(auto verifier, RsaFdhVerifier::New(public_key));
  std::string raw_unblind_sig;
  absl::Base64Unescape(unblind_sig.value(), &raw_unblind_sig);
  ASSERT_OK(verifier->Verify(crypto.original_message(), raw_unblind_sig,
                             crypto.bn_ctx()));
  BN_CTX_end(crypto.bn_ctx());
}

TEST_F(SessionCryptoTest, BlindSignWrongSigner) {
  SessionCrypto crypto(&bridge_config_aes_128_);

  BN_CTX_start(crypto.bn_ctx());
  auto rsa_f4 = BN_CTX_get(crypto.bn_ctx());
  EXPECT_TRUE(BN_set_u64(rsa_f4, RSA_F4));

  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey private_key;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey public_key;
  EXPECT_THAT(::crypto::tink::subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
                  2048, rsa_f4, &private_key, &public_key),
              testing::status::IsOk());

  ASSERT_OK_AND_ASSIGN(
      const std::string pem,
      ::crypto::tink::subtle::PemParser::WriteRsaPublicKey(public_key));

  EXPECT_OK(crypto.SetBlindingPublicKey(pem));
  auto blind_opt = crypto.GetZincBlindToken();
  EXPECT_NE(blind_opt, absl::nullopt);

  std::string raw_blind;
  absl::Base64Unescape(blind_opt.value(), &raw_blind);

  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey other_private;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey other_public;
  EXPECT_THAT(::crypto::tink::subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
                  2048, rsa_f4, &other_private, &other_public),
              testing::status::IsOk());

  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(other_private));
  ASSERT_OK_AND_ASSIGN(auto sig, signer->Sign(raw_blind));
  EXPECT_EQ(crypto.GetBrassUnblindedToken(sig), absl::nullopt);
  BN_CTX_end(crypto.bn_ctx());
}

TEST_F(SessionCryptoTest, TestInvalidPem) {
  // Some random public string.
  std::string rsa_pem = absl::StrCat(
      "-----BEGIN PUBLIC KEY-----\n",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n");

  SessionCrypto crypto(&bridge_config_aes_128_);
  EXPECT_THAT(crypto.SetBlindingPublicKey(rsa_pem),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("PEM Public Key parsing failed")));
  EXPECT_EQ(absl::nullopt, crypto.GetZincBlindToken());
}

}  // namespace
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
