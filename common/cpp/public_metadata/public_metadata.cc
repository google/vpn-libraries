#include "privacy/net/common/cpp/public_metadata/public_metadata.h"

#include <string>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"

namespace privacy::ppn {

BinaryPublicMetadata PublicMetadataProtoToStruct(
    const PublicMetadata& metadata) {
  BinaryPublicMetadata binary_struct;
  // If any fields in the struct change, we need to bump the version.
  binary_struct.version = 1;
  if (!metadata.service_type().empty()) {
    binary_struct.service_type = metadata.service_type();
  }

  if (metadata.has_exit_location()) {
    if (!metadata.exit_location().country().empty() &&
        metadata.exit_location().country().size() == 2) {
      binary_struct.country.value() = metadata.exit_location().country();
    }
    if (!metadata.exit_location().city_geo_id().empty()) {
      binary_struct.region = metadata.exit_location().city_geo_id();
    }
  }

  if (metadata.has_expiration()) {
    binary_struct.expiration_epoch_seconds = metadata.expiration().seconds();
  }
  if (metadata.debug_mode() == PublicMetadata::DEBUG_ALL) {
    binary_struct.debug_mode = 1;
  }
  return binary_struct;
}

}  // namespace privacy::ppn
