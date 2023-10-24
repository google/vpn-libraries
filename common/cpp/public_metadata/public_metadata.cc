#include "privacy/net/common/cpp/public_metadata/public_metadata.h"

#include <string>

#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/ascii.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/time.h"
#include "third_party/anonymous_tokens/cpp/privacy_pass/token_encodings.h"

namespace privacy::ppn {

using private_membership::anonymous_tokens::DebugMode;
using private_membership::anonymous_tokens::ExpirationTimestamp;
using private_membership::anonymous_tokens::Extensions;
using private_membership::anonymous_tokens::GeoHint;
using private_membership::anonymous_tokens::ProxyLayer;
using private_membership::anonymous_tokens::ServiceType;

BinaryPublicMetadata PublicMetadataProtoToStruct(
    const PublicMetadata& metadata) {
  BinaryPublicMetadata binary_struct;
  // If any fields in the struct change, we need to bump the version.
  binary_struct.version = 2;
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
  if (metadata.version < 1 || metadata.version > 2) {
    return absl::InvalidArgumentError("Binary metadata has unexpected version");
  }
  if (metadata.version == 2) {
    if (metadata.proxy_layer != 0 && metadata.proxy_layer != 1) {
      return absl::InvalidArgumentError(
          "Binary metadata has unexpected proxy layer");
    }
  }
  // Checks below included for version 1
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

absl::StatusOr<std::string> Serialize(
    const privacy::ppn::BinaryPublicMetadata& metadata) {
  Extensions extensions;
  ExpirationTimestamp expiration_timestamp;
  if (!metadata.expiration_epoch_seconds.has_value()) {
    return absl::InvalidArgumentError("missing expiration");
  }
  expiration_timestamp.timestamp = metadata.expiration_epoch_seconds.value();
  expiration_timestamp.timestamp_precision = 900;  // 15 minute granularity
  auto expiration_ext = expiration_timestamp.AsExtension();
  if (!expiration_ext.ok()) {
    return expiration_ext.status();
  }
  extensions.extensions.push_back(expiration_ext.value());

  GeoHint geo_hint;
  if (!metadata.country.has_value()) {
    return absl::InvalidArgumentError("missing country in geo information");
  }
  geo_hint.geo_hint =
      absl::StrCat(absl::AsciiStrToUpper(metadata.country.value()), ",",
                   absl::AsciiStrToUpper(metadata.region.value()), ",",
                   absl::AsciiStrToUpper(metadata.city.value()));
  auto geo_ext = geo_hint.AsExtension();
  if (!geo_ext.ok()) {
    return geo_ext.status();
  }
  extensions.extensions.push_back(geo_ext.value());

  ServiceType service_type;
  if (!metadata.service_type.has_value()) {
    return absl::InvalidArgumentError("missing service type");
  }
  if (metadata.service_type.value() == "chromeipblinding") {
    service_type.service_type_id = ServiceType::kChromeIpBlinding;
  } else {
    return absl::InvalidArgumentError("unsupported service type");
  }
  auto service_type_ext = service_type.AsExtension();
  if (!service_type_ext.ok()) {
    return service_type_ext.status();
  }
  extensions.extensions.push_back(service_type_ext.value());

  DebugMode debug_mode;
  if (metadata.debug_mode == 1) {
    debug_mode.mode = DebugMode::kDebug;
  } else if (metadata.debug_mode == 0) {
    debug_mode.mode = DebugMode::kProd;
  }
  auto debug_mode_ext = debug_mode.AsExtension();
  if (!debug_mode_ext.ok()) {
    return debug_mode_ext.status();
  }
  extensions.extensions.push_back(debug_mode_ext.value());

  if (metadata.version == 2) {
    ProxyLayer proxy_layer;
    if (metadata.proxy_layer == 0) {
      proxy_layer.layer = ProxyLayer::kProxyA;
    } else if (metadata.proxy_layer == 1) {
      proxy_layer.layer = ProxyLayer::kProxyB;
    }
    auto proxy_layer_ext = proxy_layer.AsExtension();
    if (!proxy_layer_ext.ok()) {
      return proxy_layer_ext.status();
    }
    extensions.extensions.push_back(proxy_layer_ext.value());
  }

  return private_membership::anonymous_tokens::EncodeExtensions(extensions);
}

// Deserialize a BinaryPublicMetadata extension into a struct.
absl::StatusOr<privacy::ppn::BinaryPublicMetadata> Deserialize(
    absl::string_view encoded_extensions) {
  const auto extensions =
      private_membership::anonymous_tokens::DecodeExtensions(
          encoded_extensions);
  if (!extensions.ok()) {
    return extensions.status();
  }
  // TODO: b/306703210 - propagate version information
  if (extensions->extensions.size() != 4 &&
      extensions->extensions.size() != 5) {
    return absl::InvalidArgumentError("Wrong number of extensions");
  }
  auto expiration =
      ExpirationTimestamp::FromExtension(extensions->extensions[0]);
  if (!expiration.ok()) {
    return expiration.status();
  }
  if (expiration.value().timestamp_precision != 900) {
    return absl::InvalidArgumentError("Invalid timestamp_precision");
  }
  auto geo_hint = GeoHint::FromExtension(extensions->extensions[1]);
  if (!geo_hint.ok()) {
    return geo_hint.status();
  }
  auto service_type = ServiceType::FromExtension(extensions->extensions[2]);
  if (!service_type.ok()) {
    return service_type.status();
  }
  if (service_type->service_type != "chromeipblinding") {
    return absl::InvalidArgumentError("Unsupported service type");
  }
  auto debug_mode = DebugMode::FromExtension(extensions->extensions[3]);
  if (!debug_mode.ok()) {
    return debug_mode.status();
  }

  BinaryPublicMetadata metadata;
  if (extensions->extensions.size() == 5) {
    auto proxy_layer = ProxyLayer::FromExtension(extensions->extensions[4]);
    if (!proxy_layer.ok()) {
      return proxy_layer.status();
    }
    metadata.version = 2;
    metadata.proxy_layer = proxy_layer->layer;
  } else {
    metadata.version = 1;
  }

  metadata.expiration_epoch_seconds = expiration.value().timestamp;
  metadata.country = geo_hint->country_code;
  metadata.region = geo_hint->region;
  metadata.city = geo_hint->city;
  metadata.debug_mode = debug_mode->mode;
  metadata.service_type = service_type->service_type;
  return metadata;
}

}  // namespace privacy::ppn
