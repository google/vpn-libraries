#include "privacy/net/common/cpp/public_metadata/fingerprint.h"

#include <cstdint>
#include <string>
#include <vector>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/numbers.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/openssl/digest.h"

namespace privacy::ppn {
namespace {

template <typename T>
std::string OmitDefault(T value) {
  return value == 0 ? "" : absl::StrCat(value);
}

}  // namespace

absl::Status FingerprintPublicMetadata(const PublicMetadata& metadata,
                                       uint64_t* fingerprint) {
  // copybara.strip_begin(internal)
  // LINT.IfChange
  // copybara.strip_end
  const EVP_MD* hasher = EVP_sha256();
  std::string digest;
  digest.resize(EVP_MAX_MD_SIZE);

  uint32_t digest_length = 0;
  // Concatenate fields in tag number order, omitting fields whose values match
  // the default. This enables new fields to be added without changing the
  // resulting encoding.
  const std::vector<std::string> parts = {
      metadata.exit_location().country(),
      metadata.exit_location().city_geo_id(),
      metadata.service_type(),
      OmitDefault(metadata.expiration().seconds()),
      OmitDefault(metadata.expiration().nanos()),
  };
  // The signer needs to ensure that | is not allowed in any metadata value so
  // intentional collisions cannot be created.
  const std::string input = absl::StrJoin(parts, "|");
  if (EVP_Digest(input.data(), input.length(),
                 reinterpret_cast<uint8_t*>(&digest[0]), &digest_length, hasher,
                 nullptr) != 1) {
    return absl::InternalError("EVP_Digest failed");
  }
  // Return the first uint64_t of the SHA-256 hash.
  memcpy(fingerprint, digest.data(), sizeof(*fingerprint));
  return absl::OkStatus();
  // copybara.strip_begin(internal)
  // LINT.ThenChange(//depot/google3/third_party/quiche/blind_sign_auth/blind_sign_auth.cc)
  // copybara.strip_end
}

}  // namespace privacy::ppn
