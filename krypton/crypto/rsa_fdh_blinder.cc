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

#include "privacy/net/krypton/crypto/rsa_fdh_blinder.h"

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "privacy/net/krypton/crypto/openssl_error.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/base/log_severity.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bio.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/rsa.h"
#include "third_party/sha3/sha3.h"

namespace privacy {
namespace krypton {
namespace crypto {

namespace {
constexpr int kBsslSuccess = 1;

absl::StatusOr<std::string> BignumToString(const BIGNUM* in, size_t out_len) {
  std::vector<uint8_t> serialization(out_len);
  if (BN_bn2bin_padded(serialization.data(), serialization.size(), in) !=
      kBsslSuccess) {
    return absl::InternalError("BN_bn2bin failed.");
  }
  return std::string(std::make_move_iterator(serialization.begin()),
                     std::make_move_iterator(serialization.end()));
}

// Note the returned `BIGNUM*` is allocated on the active `bn_ctx`.
// Therefor this must be called in between cals to `BN_CTX_start` and
// `BN_CTX_end`.
absl::StatusOr<BIGNUM*> StringToBignum(const absl::string_view in,
                                       BN_CTX* bn_ctx) {
  auto out = BN_CTX_get(bn_ctx);
  BN_bin2bn(reinterpret_cast<const uint8_t*>(in.data()), in.size(), out);
  if (out == nullptr) {
    return absl::InternalError("BN_bin2bn failed.");
  }
  return out;
}

// Full domain hash using SHAKE256.
// Note the returned `BIGNUM*` is allocated on the active `bn_ctx`.
// Therefor this must be called in between cals to `BN_CTX_start` and
// `BN_CTX_end`.
absl::StatusOr<BIGNUM*> Shake256Fdh(const absl::string_view data,
                                    const RSA* signer_public_key,
                                    BN_CTX* bn_ctx) {
  const auto number_bytes = RSA_size(signer_public_key) + 64;  // flooding

  // Compute the SHAKE256(data) and reduce modulo n.
  std::vector<uint8_t> hash(number_bytes);

  third_party_sha3::Shake256 h;
  h.Write(reinterpret_cast<const unsigned char*>(data.data()), data.size());
  h.Read(hash.data(), number_bytes);

  BIGNUM* hash_bn = BN_CTX_get(bn_ctx);
  if (BN_bin2bn(hash.data(), number_bytes, hash_bn) == nullptr) {
    return absl::InternalError("BN_bin2bn failed.");
  }

  // Take the result modulo n.
  BIGNUM* hash_mod_n = BN_CTX_get(bn_ctx);
  if (BN_mod(hash_mod_n, hash_bn, RSA_get0_n(signer_public_key), bn_ctx) !=
      kBsslSuccess) {
    return absl::InternalError("Error during BN_mod.");
  }

  return hash_mod_n;
}

class CtxEnder {
 public:
  explicit CtxEnder(BN_CTX* bn_ctx) : bn_ctx_(bn_ctx) { BN_CTX_start(bn_ctx_); }

  ~CtxEnder() { BN_CTX_end(bn_ctx_); }

 private:
  BN_CTX* bn_ctx_;  // not owned
};

}  // namespace

RsaFdhBlinder::RsaFdhBlinder(bssl::UniquePtr<BIGNUM> r,
                             bssl::UniquePtr<RSA> public_key,
                             bssl::UniquePtr<BN_MONT_CTX> mont_n,
                             std::string blind)
    : r_(std::move(r)),
      public_key_(std::move(public_key)),
      mont_n_(std::move(mont_n)),
      blind_(std::move(blind)) {}

absl::StatusOr<std::unique_ptr<RsaFdhBlinder>> RsaFdhBlinder::Blind(
    const absl::string_view message, bssl::UniquePtr<RSA> signer_public_key,
    BN_CTX* bn_ctx) {
  // For use in blind construction.
  CtxEnder ender(bn_ctx);

  const auto n = RSA_get0_n(signer_public_key.get());
  const auto mod_size = RSA_size(signer_public_key.get());

  bssl::UniquePtr<BIGNUM> r(BN_new());
  if (r.get() == nullptr) {
    return absl::InternalError("r allocation failed");
  }
  // Limit r between [2, n) so that an r of 1 never happens. An r of 1 doesn't
  // blind.
  if (BN_rand_range_ex(r.get(), 2, n) != kBsslSuccess) {
    return absl::InternalError("BN_rand_range_ex failed");
  }

  bssl::UniquePtr<BN_MONT_CTX> mont_n(
      BN_MONT_CTX_new_for_modulus(RSA_get0_n(signer_public_key.get()), bn_ctx));
  if (!mont_n) {
    return absl::InternalError("BN_MONT_CTX_new_for_modulus failed");
  }

  // take `r^e mod n`. This is an equivalent operation to RSA_encrypt, without
  // extra encode/decode trips.
  BIGNUM* rE = BN_CTX_get(bn_ctx);
  if (BN_mod_exp_mont(rE, r.get(), RSA_get0_e(signer_public_key.get()),
                      RSA_get0_n(signer_public_key.get()), bn_ctx,
                      mont_n.get()) != kBsslSuccess) {
    return absl::InternalError("BN_mod_exp_mont failed.");
  }

  PPN_ASSIGN_OR_RETURN(const auto hash,
                       Shake256Fdh(message, signer_public_key.get(), bn_ctx));

  // To avoid leaking side channels, we use Montgomery reduction. This would be
  // FromMontgomery(ModMulMontgomery(ToMontgomery(m), ToMontgomery(r^e))).
  // However, this is equivalent to ModMulMontgomery(m, ToMontgomery(r^e)).
  // Each BN_mod_mul_montgomery removes a factor of R, so by having only one
  // input in the Montgomery domain, we save a To/FromMontgomery pair.
  //
  // Internally, BN_mod_exp_mont actually computes r^e in the Montgomery domain
  // and converts it out, but there is no public API for this, so we perform an
  // extra conversion.
  auto blinded_hash = BN_CTX_get(bn_ctx);
  if (BN_to_montgomery(blinded_hash, rE, mont_n.get(), bn_ctx) !=
          kBsslSuccess ||
      BN_mod_mul_montgomery(blinded_hash, hash, blinded_hash, mont_n.get(),
                            bn_ctx) != kBsslSuccess) {
    return absl::InternalError("Multiplying hash and rE failed");
  }

  PPN_ASSIGN_OR_RETURN(const std::string blinded_hash_str,
                       BignumToString(blinded_hash, /*out_len*/ mod_size));

  auto blinded = absl::WrapUnique(
      new RsaFdhBlinder(std::move(r),
                        /*public_key*/ std::move(signer_public_key),
                        std::move(mont_n), std::move(blinded_hash_str)));

  return blinded;
}

absl::StatusOr<std::string> RsaFdhBlinder::Unblind(
    const absl::string_view blind_signature, BN_CTX* bn_ctx) const {
  if (r_.get() == nullptr) {
    return absl::InternalError("r_ null.");
  }
  if (public_key_.get() == nullptr) {
    return absl::InternalError("public_key_ null.");
  }

  CtxEnder ender(bn_ctx);

  unsigned int mod_size = RSA_size(public_key_.get());

  // Parse the signed_blinded_data as BIGNUM.
  if (blind_signature.size() != mod_size) {
    return absl::InternalError(absl::StrCat(
        "Expected = ", mod_size, " got = ", blind_signature.size(), " bytes."));
  }
  PPN_ASSIGN_OR_RETURN(BIGNUM * signed_big,
                       StringToBignum(blind_signature, bn_ctx));

  // We wish to compute r^-1 in the Montgomery domain, or r^-1 R mod n. This is
  // can be done with BN_mod_inverse_blinded followed by BN_to_montgomery, but
  // it is equivalent and slightly more efficient to first compute r R^-1 mod n
  // with BN_from_montgomery, and then inverting that to give r^-1 R mod n.
  auto r_inv_mont = BN_CTX_get(bn_ctx);
  int no_inverse = 0;
  if (BN_from_montgomery(r_inv_mont, r_.get(), mont_n_.get(), bn_ctx) !=
          kBsslSuccess ||
      BN_mod_inverse_blinded(r_inv_mont, &no_inverse, r_inv_mont, mont_n_.get(),
                             bn_ctx) != kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("BN_mod_inverse failed no_inverse=", no_inverse));
  }

  // To avoid leaking side channels, we use Montgomery reduction. This would be
  // FromMontgomery(ModMulMontgomery(ToMontgomery(m), ToMontgomery(r^-1))).
  // However, this is equivalent to ModMulMontgomery(m, ToMontgomery(r^-1)).
  // Each BN_mod_mul_montgomery removes a factor of R, so by having only one
  // input in the Montgomery domain, we save a To/FromMontgomery pair.
  auto unblinded_sig_big = BN_CTX_get(bn_ctx);
  if (BN_mod_mul_montgomery(unblinded_sig_big, signed_big, r_inv_mont,
                            mont_n_.get(), bn_ctx) != kBsslSuccess) {
    return absl::InternalError("BN_mod_mul failed.");
  }

  return BignumToString(unblinded_sig_big,
                        /*out_bytes*/ BN_num_bytes(unblinded_sig_big));
}

absl::StatusOr<std::unique_ptr<RsaFdhBlindSigner>> RsaFdhBlindSigner::New(
    const ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPrivateKey&
        private_key) {
  PPN_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> private_key_bssl,
                       ::crypto::tink::subtle::SubtleUtilBoringSSL::
                           BoringSslRsaFromRsaPrivateKey(private_key));

  return absl::WrapUnique(new RsaFdhBlindSigner(std::move(private_key_bssl)));
}

absl::StatusOr<std::string> RsaFdhBlindSigner::Sign(
    const absl::string_view blinded_data) const {
  const uint32_t mod_size = RSA_size(signing_key_.get());

  // Compute a raw RSA signature.
  std::vector<uint8_t> out(mod_size);
  size_t out_len;
  if (RSA_sign_raw(signing_key_.get(), &out_len, out.data(),
                   /*max_out*/ mod_size,
                   reinterpret_cast<const uint8_t*>(blinded_data.data()),
                   blinded_data.size(), RSA_NO_PADDING) != kBsslSuccess) {
    return GetOpenSSLError("RSA_sign_raw failed");
  }
  if (out_len != mod_size) {
    return absl::InternalError(
        absl::StrCat("Expected = ", mod_size, " got = ", out_len, " bytes."));
  }

  return std::string(std::make_move_iterator(out.begin()),
                     std::make_move_iterator(out.end()));
}

absl::StatusOr<std::unique_ptr<RsaFdhVerifier>> RsaFdhVerifier::New(
    const ::crypto::tink::subtle::SubtleUtilBoringSSL::RsaPublicKey&
        public_key) {
  // The RSA n and e are checked as part of the conversion.
  PPN_ASSIGN_OR_RETURN(
      bssl::UniquePtr<RSA> public_key_bssl,
      ::crypto::tink::subtle::SubtleUtilBoringSSL::BoringSslRsaFromRsaPublicKey(
          public_key));

  return absl::WrapUnique(new RsaFdhVerifier(std::move(public_key_bssl)));
}

absl::Status RsaFdhVerifier::Verify(const absl::string_view message,
                                    const absl::string_view signature,
                                    BN_CTX* bn_ctx) const {
  CtxEnder ender(bn_ctx);

  const uint32_t mod_size = RSA_size(verification_key_.get());

  PPN_ASSIGN_OR_RETURN(const BIGNUM* hash_bn,
                       Shake256Fdh(message, verification_key_.get(), bn_ctx));
  PPN_ASSIGN_OR_RETURN(const std::string hash,
                       BignumToString(hash_bn, mod_size));

  size_t out_len;
  std::vector<uint8_t> resulting_hash(mod_size);
  if (RSA_verify_raw(verification_key_.get(), &out_len, resulting_hash.data(),
                     /*max_out = */ mod_size,
                     reinterpret_cast<const unsigned char*>(signature.data()),
                     signature.size(), RSA_NO_PADDING) != kBsslSuccess) {
    return GetOpenSSLError("Error during signature verification");
  }
  if (out_len != mod_size) {
    return absl::InternalError(
        absl::StrCat("Expected = ", mod_size, " got = ", out_len, " bytes."));
  }

  if (hash ==
      absl::string_view(reinterpret_cast<const char*>(resulting_hash.data()),
                        resulting_hash.size())) {
    return absl::OkStatus();  // signature is valid.
  }
  return absl::InvalidArgumentError("Verification failed.");
}

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
