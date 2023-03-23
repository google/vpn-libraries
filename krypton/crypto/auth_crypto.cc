// Copyright 2023 Google LLC
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

#include <optional>
#include <string>

#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/tink/cc/subtle/pem_parser_boringssl.h"
#include "third_party/tink/cc/subtle/random.h"
#include "third_party/tink/cc/subtle/subtle_util_boringssl.h"

namespace privacy {
namespace krypton {
namespace crypto {
namespace {
constexpr char kAlphabet[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::string RandomUTF8String(size_t len, absl::string_view alphabet) {
  std::string result(len, '\0');
  const int k = alphabet.size();
  for (char& c : result) {
    auto idx = ::crypto::tink::subtle::Random::GetRandomUInt8();
    c = alphabet[idx % k];
  }
  // Add a structure, for more context
  return absl::StrCat("blind:", result);
}

}  // namespace

AuthCrypto::AuthCrypto(const KryptonConfig& config)
    : bn_ctx_(BN_CTX_new()), config_(config) {
  DCHECK_NE(bn_ctx_.get(), nullptr);
  // Generate another random 32 byte string that is used as blind message.
  original_message_ = RandomUTF8String(32, kAlphabet);
}

absl::Status AuthCrypto::SetBlindingPublicKey(absl::string_view rsa_public) {
  using ::crypto::tink::subtle::SubtleUtilBoringSSL;
  PPN_ASSIGN_OR_RETURN(
      const auto subtle_rsa_public_key,
      ::crypto::tink::subtle::PemParser::ParseRsaPublicKey(rsa_public));

  if (subtle_rsa_public_key == nullptr) {
    LOG(ERROR) << "RSA public key is null";
    return absl::FailedPreconditionError("RSA public key is null");
  }
  // Ensure the modulus is large enough to be considered a safe key.
  // https://www.keylength.com/en/4/
  PPN_ASSIGN_OR_RETURN(const auto n_big,
                       SubtleUtilBoringSSL::str2bn(subtle_rsa_public_key->n));
  PPN_RETURN_IF_ERROR(
      SubtleUtilBoringSSL::ValidateRsaModulusSize(BN_num_bits(n_big.get())));

  // Ensure the exponent is large enough as well.
  PPN_RETURN_IF_ERROR(
      SubtleUtilBoringSSL::ValidateRsaPublicExponent(subtle_rsa_public_key->e));

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
      RsaFdhBlinder::Blind(original_message_, std::move(bssl_unique_rsa),
                           bn_ctx_.get()));

  PPN_ASSIGN_OR_RETURN(
      auto hash, ::crypto::tink::subtle::boringssl::ComputeHash(rsa_public,
                                                                *EVP_sha256()));
  blind_signing_public_key_hash_ = std::string(hash.begin(), hash.end());

  return absl::OkStatus();
}

std::optional<std::string> AuthCrypto::GetZincBlindToken() const {
  if (blinder_ == nullptr) {
    return std::nullopt;
  }
  return absl::Base64Escape(blinder_->blind());
}

std::optional<std::string> AuthCrypto::GetBrassUnblindedToken(
    absl::string_view zinc_blind_signature) const {
  if (blinder_ == nullptr) {
    LOG(ERROR) << "blinder_ is null";
    return std::nullopt;
  }
  auto unblind_signature =
      blinder_->Unblind(zinc_blind_signature, bn_ctx_.get());
  if (!unblind_signature.ok()) {
    LOG(ERROR) << "Unblinding failed: " << unblind_signature.status();
    return std::nullopt;
  }
  auto verify_result =
      verifier_->Verify(original_message_, *unblind_signature, bn_ctx_.get());
  if (!verify_result.ok()) {
    LOG(ERROR) << "Verify of original_message_ failed: " << verify_result;
    return std::nullopt;
  }
  return absl::Base64Escape(*unblind_signature);
}

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
