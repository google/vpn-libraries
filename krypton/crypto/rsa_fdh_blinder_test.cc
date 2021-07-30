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

#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"

#include <cstdio>
#include <ostream>
#include <vector>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bio.h"
#include "third_party/openssl/bn.h"
#include "third_party/tink/cc/subtle/subtle_util_boringssl.h"

namespace privacy {
namespace krypton {
namespace crypto {

namespace {
using ::testing::status::IsOk;
using ::testing::status::StatusIs;
}  // namespace

class RsaFdhBlinderTest : public ::testing::Test {
 public:
  RsaFdhBlinderTest() : bn_ctx_(BN_CTX_new()) {
    BN_CTX_start(bn_ctx_.get());
    rsa_f4_ = BN_CTX_get(bn_ctx_.get());
    EXPECT_TRUE(BN_set_u64(rsa_f4_, RSA_F4));
    EXPECT_THAT(::crypto::tink::subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
                    2048, rsa_f4_, &private_key_, &public_key_),
                IsOk());
    BN_CTX_end(bn_ctx_.get());
  }

 protected:
  void SetUp() override {
    // The RSA modulus and exponent are checked as part of the conversion to
    // bssl::UniquePtr<RSA>.
    ASSERT_OK_AND_ASSIGN(rsa_public_key_,
                         ::crypto::tink::subtle::SubtleUtilBoringSSL::
                             BoringSslRsaFromRsaPublicKey(public_key_));
    ASSERT_OK_AND_ASSIGN(rsa_private_key_,
                         ::crypto::tink::subtle::SubtleUtilBoringSSL::
                             BoringSslRsaFromRsaPrivateKey(private_key_));
  }

  bssl::UniquePtr<RSA> public_key_copy() const {
    bssl::UniquePtr<RSA> public_key_copy(
        RSAPublicKey_dup(rsa_public_key_.get()));
    EXPECT_THAT(public_key_copy.get(), testing::NotNull());
    return public_key_copy;
  }

  bssl::UniquePtr<BN_CTX> bn_ctx_;
  BIGNUM* rsa_f4_;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey private_key_;
  ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey public_key_;

 private:
  // Initialized after SetUp
  bssl::UniquePtr<RSA> rsa_public_key_;
  bssl::UniquePtr<RSA> rsa_private_key_;
};

TEST_F(RsaFdhBlinderTest, E2eWorks) {
  ASSERT_OK_AND_ASSIGN(auto verifier, RsaFdhVerifier::New(public_key_));
  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(private_key_));

  const absl::string_view message = "Hello World!";

  ASSERT_OK_AND_ASSIGN(
      auto blinded,
      RsaFdhBlinder::Blind(message, public_key_copy(), bn_ctx_.get()));

  ASSERT_OK_AND_ASSIGN(std::string blinded_signature,
                       signer->Sign(blinded->blind()));
  ASSERT_OK_AND_ASSIGN(std::string signature,
                       blinded->Unblind(blinded_signature, bn_ctx_.get()));

  ASSERT_OK(verifier->Verify(message, signature, bn_ctx_.get()));
}

TEST_F(RsaFdhBlinderTest, InvalidSignature) {
  ASSERT_OK_AND_ASSIGN(auto verifier, RsaFdhVerifier::New(public_key_));
  ASSERT_OK_AND_ASSIGN(auto signer, RsaFdhBlindSigner::New(private_key_));

  const absl::string_view message = "Hello World!";

  ASSERT_OK_AND_ASSIGN(
      auto blinded,
      RsaFdhBlinder::Blind(message, public_key_copy(), bn_ctx_.get()));
  ASSERT_OK_AND_ASSIGN(std::string blinded_signature,
                       signer->Sign(blinded->blind()));
  ASSERT_OK_AND_ASSIGN(std::string signature,
                       blinded->Unblind(blinded_signature, bn_ctx_.get()));

  ASSERT_OK(verifier->Verify(message, signature, bn_ctx_.get()));

  // Invalidate the signature by zeroing the last 10 bytes.
  for (int i = 0; i < 10; i++) signature.pop_back();
  for (int i = 0; i < 10; i++) signature.push_back(0);

  EXPECT_THAT(verifier->Verify(message, signature, bn_ctx_.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("Verification")));
}

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
