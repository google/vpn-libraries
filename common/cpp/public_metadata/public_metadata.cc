#include "privacy/net/common/cpp/public_metadata/public_metadata.h"

#include <string>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/ascii.h"
#include "third_party/absl/time/time.h"

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

absl::Status ValidateBinaryPublicMetadataCardinality(
    const privacy::ppn::BinaryPublicMetadata& metadata, absl::Time now) {
  // If the version changes, then the fields have changed.
  if (metadata.version != 1) {
    return absl::InvalidArgumentError(
        "Binary metadata version is incompatible");
  }
  if (!metadata.service_type.has_value()) {
    return absl::InvalidArgumentError(
        "Binary metadata is missing service type");
  }
  // We will add new service types when they're deployed.
  if (metadata.service_type != "chromeipblinding") {
    return absl::InvalidArgumentError(
        "Binary metadata has unexpected service type");
  }
  if (!metadata.country.has_value()) {
    return absl::InvalidArgumentError("Binary metadata is missing country");
  }
  if (metadata.country->length() != 2) {
    return absl::InvalidArgumentError(
        "Binary metadata has unexpected country length");
  }
  for (char c : metadata.country.value()) {
    if (!absl::ascii_isupper(c)) {
      return absl::InvalidArgumentError(
          "Binary metadata country must be all uppercase");
    }
  }
  if (!metadata.expiration_epoch_seconds.has_value()) {
    return absl::InvalidArgumentError("Binary metadata is missing expiration");
  }
  // expiration_epoch_seconds must be rounded to a 15-minute cutoff.
  if (metadata.expiration_epoch_seconds.value() % 900 != 0) {
    return absl::InvalidArgumentError(
        "Binary metadata expiration is not rounded");
  }
  absl::Time expiration_time =
      absl::FromUnixSeconds(metadata.expiration_epoch_seconds.value());
  if (expiration_time < now || expiration_time > now + absl::Hours(168)) {
    return absl::InvalidArgumentError("Binary metadata has expired");
  }
  return absl::OkStatus();
}

// TODO: describe
std::string Serialize(const privacy::ppn::BinaryPublicMetadata& /*metadata*/) {
  // To be implemented.
  return "";
}

// Deserialize a BinaryPublicMetadata extension into a struct.
privacy::ppn::BinaryPublicMetadata Deserialize(
    absl::string_view /*serialized_metadata*/) {
  // To be implemented.
  return {};
}

}  // namespace privacy::ppn
