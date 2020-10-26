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

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/types/optional.h"
#include "third_party/openssl/curve25519.h"
#include "third_party/tink/cc/public_key_verify.h"

namespace privacy {
namespace krypton {
namespace crypto {

namespace {

using ::testing::EqualsProto;
using ::testing::HasSubstr;
using ::testing::status::IsOkAndHolds;
using ::testing::status::StatusIs;

TEST(SessionCryptoTest, TestInitialKeyGeneration) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;
  LOG(INFO) << "Private Key "
            << absl::Base64Escape(local_crypto.PrivateKeyTestOnly());

  EXPECT_EQ(X25519_PRIVATE_KEY_LEN, local_crypto.PrivateKeyTestOnly().length());

  auto key_material = local_crypto.GetMyKeyMaterial();
  std::string unescaped_public;
  auto local_keys = local_crypto.GetMyKeyMaterial();
  absl::Base64Unescape(local_keys.public_value, &unescaped_public);
  EXPECT_EQ(X25519_PUBLIC_VALUE_LEN, unescaped_public.length());
}

TEST(SessionCryptoTest, TestSharedKeyBeforeSettingPublicValue) {
  SessionCrypto local_crypto;

  EXPECT_THAT(local_crypto.SharedKeyBase64TestOnly(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SessionCryptoTest, TestSharedKey) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;

  auto local_keys = local_crypto.GetMyKeyMaterial();
  auto remote_keys = remote_crypto.GetMyKeyMaterial();

  EXPECT_OK(local_crypto.SetRemoteKeyMaterial(remote_keys.public_value,
                                              remote_keys.nonce));

  EXPECT_OK(remote_crypto.SetRemoteKeyMaterial(local_keys.public_value,
                                               local_keys.nonce));
  EXPECT_EQ(local_crypto.SharedKeyBase64TestOnly(),
            remote_crypto.SharedKeyBase64TestOnly());
}

TEST(SessionCryptoTest, TestIpSecTransformFailure) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;
  EXPECT_THAT(local_crypto.GetIpSecTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SessionCryptoTest, TestIpSecTransformParams) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;

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

  auto status_or_local_ipsec_params = local_crypto.GetIpSecTransformParams();
  EXPECT_OK(status_or_local_ipsec_params);
  ASSERT_OK_AND_ASSIGN(auto local_ipsec_params, status_or_local_ipsec_params);

  EXPECT_EQ(32, local_ipsec_params.downlink_key().length());
  EXPECT_EQ(32, local_ipsec_params.uplink_key().length());
  EXPECT_EQ(4, local_ipsec_params.uplink_salt().length());
  EXPECT_EQ(4l, local_ipsec_params.downlink_salt().length());

  EXPECT_THAT(remote_crypto.GetIpSecTransformParams(),
              IsOkAndHolds(EqualsProto(local_ipsec_params)));
}

TEST(SessionCryptoTest, TestBridgeTransformFailure) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;
  EXPECT_THAT(local_crypto.GetBridgeTransformParams(CryptoSuite::AES128_GCM),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SessionCryptoTest, TestBridgeTransformParams128) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;

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

  auto status_or_bridge_transform_params =
      local_crypto.GetBridgeTransformParams(CryptoSuite::AES128_GCM);
  EXPECT_OK(status_or_bridge_transform_params);
  ASSERT_OK_AND_ASSIGN(auto local_bridge_params,
                       status_or_bridge_transform_params);

  EXPECT_EQ(16, local_bridge_params.downlink_key().length());
  EXPECT_EQ(16, local_bridge_params.uplink_key().length());

  EXPECT_THAT(remote_crypto.GetBridgeTransformParams(CryptoSuite::AES128_GCM),
              IsOkAndHolds(EqualsProto(local_bridge_params)));
}

TEST(SessionCryptoTest, TestBridgeTransformParams256) {
  SessionCrypto local_crypto;
  SessionCrypto remote_crypto;

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

  auto status_or_bridge_transform_params =
      local_crypto.GetBridgeTransformParams(CryptoSuite::AES256_GCM);
  EXPECT_OK(status_or_bridge_transform_params);
  ASSERT_OK_AND_ASSIGN(auto local_bridge_params,
                       status_or_bridge_transform_params);

  EXPECT_EQ(32, local_bridge_params.downlink_key().length());
  EXPECT_EQ(32, local_bridge_params.uplink_key().length());

  EXPECT_THAT(remote_crypto.GetBridgeTransformParams(CryptoSuite::AES256_GCM),
              IsOkAndHolds(EqualsProto(local_bridge_params)));
}

TEST(SessionCryptoTest, VerifyRekey) {
  // Here the steps to verify rekey.
  // Step 1: Two session crypto keys previous (one exchanged earlier) and the
  // current one.
  // Step 2: Generate a signature based on current crypto public value and old
  // verification key.
  // Step 3: Validate the current public value signature matches.
  SessionCrypto previous;
  SessionCrypto current;
  std::string verification_key;
  std::string signature;
  std::string current_public_value;

  absl::Base64Unescape(current.GetMyKeyMaterial().public_value,
                       &current_public_value);

  auto status_or_verification_key = previous.GetRekeyVerificationKey();
  EXPECT_OK(status_or_verification_key);
  absl::Base64Unescape(status_or_verification_key.ValueOrDie(),
                       &verification_key);

  // Use previous ed25519 to generate a signature using the current public
  // value.
  auto status_or_signature =
      previous.GenerateSignature(current.GetMyKeyMaterial().public_value);
  EXPECT_OK(status_or_signature);
  absl::Base64Unescape(status_or_signature.ValueOrDie(), &signature);

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

TEST(SessionCryptoTest, TestSuccessfulBlindSigning) {
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

  SessionCrypto crypto;
  EXPECT_OK(crypto.SetBlindingPublicKey(rsa_pem));
  auto optional_blind = crypto.GetZincBlindToken();
  EXPECT_NE(optional_blind, absl::nullopt);
  EXPECT_NE(optional_blind.value().size(), 0);
  // This is the SHA256 of the hardcoded |rsa_pem| above.
  EXPECT_EQ(crypto.blind_signing_public_key_hash(),
            "aV07BUI5y+F8E/ESXXZRx8cKh0lT4J4VBDjlOl25850=");
}

TEST(SessionCryptoTest, TestInvalidPem) {
  // Some random public string.
  std::string rsa_pem = absl::StrCat(
      "-----BEGIN PUBLIC KEY-----\n",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n");

  SessionCrypto crypto;
  EXPECT_THAT(crypto.SetBlindingPublicKey(rsa_pem),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("PEM Public Key parsing failed")));
  EXPECT_EQ(absl::nullopt, crypto.GetZincBlindToken());
}


}  // namespace
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
