#ifndef PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_FINGERPRINT_H_
#define PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_FINGERPRINT_H_

#include <cstdint>

#include "privacy/net/common/proto/public_metadata.proto.h"
#include "third_party/absl/status/status.h"

namespace privacy::ppn {

// Produces a canonical 64-bit fingerprint of a PublicMetadata proto for use in
// blind signing.
absl::Status FingerprintPublicMetadata(
    const privacy::ppn::PublicMetadata& metadata, uint64_t* fingerprint);

}  // namespace privacy::ppn

#endif  // PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_FINGERPRINT_H_
