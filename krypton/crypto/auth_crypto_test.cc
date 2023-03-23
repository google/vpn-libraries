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

#include "privacy/net/krypton/crypto/auth_crypto.h"

#include <string>

#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/tink/cc/subtle/pem_parser_boringssl.h"

namespace privacy {
namespace krypton {
namespace crypto {
namespace {

using ::testing::HasSubstr;
using ::testing::status::StatusIs;

TEST(AuthCryptoTest, BlindingOk) {
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

  KryptonConfig config_;
  AuthCrypto crypto(config_);
  EXPECT_OK(crypto.SetBlindingPublicKey(rsa_pem));
  auto optional_blind = crypto.GetZincBlindToken();
  EXPECT_NE(optional_blind, std::nullopt);
  EXPECT_NE(optional_blind.value().size(), 0);
  // This is the SHA256 of the hardcoded |rsa_pem| above.
  EXPECT_EQ(crypto.blind_signing_public_key_hash(),
            "aV07BUI5y+F8E/ESXXZRx8cKh0lT4J4VBDjlOl25850=");
}

TEST(AuthCryptoTest, BlindSignOk) {
  KryptonConfig config_;
  AuthCrypto crypto(config_);

  BN_CTX_start(crypto.bn_ctx());
  absl::Cleanup cleanup = [ctx = crypto.bn_ctx()] { BN_CTX_end(ctx); };
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
  EXPECT_NE(blind_opt, std::nullopt);

  std::string raw_blind;
  absl::Base64Unescape(blind_opt.value(), &raw_blind);

  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(private_key));
  ASSERT_OK_AND_ASSIGN(auto sig, signer->Sign(raw_blind));

  auto unblind_sig = crypto.GetBrassUnblindedToken(sig);
  ASSERT_NE(unblind_sig, std::nullopt);

  ASSERT_OK_AND_ASSIGN(auto verifier, RsaFdhVerifier::New(public_key));
  std::string raw_unblind_sig;
  absl::Base64Unescape(unblind_sig.value(), &raw_unblind_sig);
  ASSERT_OK(verifier->Verify(crypto.original_message(), raw_unblind_sig,
                             crypto.bn_ctx()));
}

TEST(AuthCryptoTest, BlindSignWrongSigner) {
  KryptonConfig config_;
  AuthCrypto crypto(config_);

  BN_CTX_start(crypto.bn_ctx());
  absl::Cleanup cleanup = [ctx = crypto.bn_ctx()] { BN_CTX_end(ctx); };
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
  EXPECT_NE(blind_opt, std::nullopt);

  std::string raw_blind;
  absl::Base64Unescape(blind_opt.value(), &raw_blind);

  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey other_private;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey other_public;
  EXPECT_THAT(::crypto::tink::subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
                  2048, rsa_f4, &other_private, &other_public),
              testing::status::IsOk());

  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(other_private));
  ASSERT_OK_AND_ASSIGN(auto sig, signer->Sign(raw_blind));
  EXPECT_EQ(crypto.GetBrassUnblindedToken(sig), std::nullopt);
}

TEST(AuthCryptoTest, TestInvalidPem) {
  // Some random public string.
  std::string rsa_pem = absl::StrCat(
      "-----BEGIN PUBLIC KEY-----\n",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n");

  KryptonConfig config_;
  AuthCrypto crypto(config_);
  EXPECT_THAT(crypto.SetBlindingPublicKey(rsa_pem),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("PEM Public Key parsing failed")));
  EXPECT_EQ(std::nullopt, crypto.GetZincBlindToken());
}
}  // namespace
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
