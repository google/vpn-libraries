#ifndef PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_PUBLIC_METADATA_H_
#define PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_PUBLIC_METADATA_H_

#include <cstdint>
#include <optional>
#include <string>

#include "privacy/net/common/proto/public_metadata.proto.h"

namespace privacy::ppn {

struct BinaryPublicMetadata {
  // Incrememented with each version of this struct to allow for safe evolution
  // of the struct.
  uint32_t version;
  // A fixed string for each service type that needs differentiation at the
  // server.
  std::optional<std::string> service_type;
  // 2 character Country or Alpha2Code as defined by rfc8805 Section 2.1.1.2
  std::optional<std::string> country;
  // Usually 5 character Region like US-CA (California) as defined by rfc8805
  // Section 2.1.1.3
  std::optional<std::string> region;
  // UTF-8 city name as defined by rfc8805 Section 2.1.1.4
  std::optional<std::string> city;
  // Seconds since epoch, rounded to the next 15 minute cutoff.
  std::optional<uint64_t> expiration_epoch_seconds;
  // copybara:strip_begin(doc is internal)
  // See go/beryllium-geo-override for details.
  // copybara:strip_end
  // Indicates the debug context of this payload.
  // 0 is UNSPECIFIED, and 1 is DEBUG_ALL.
  uint32_t debug_mode;
};

BinaryPublicMetadata PublicMetadataProtoToStruct(
    const privacy::ppn::PublicMetadata& metadata);

}  // namespace privacy::ppn

#endif  // PRIVACY_NET_COMMON_CPP_PUBLIC_METADATA_PUBLIC_METADATA_H_
