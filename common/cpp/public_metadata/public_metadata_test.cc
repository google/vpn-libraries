#include "privacy/net/common/cpp/public_metadata/public_metadata.h"

#include <cstdint>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/time/time.h"

namespace privacy::ppn {
namespace {

TEST(BinaryPublicMetadataSerialize, RoundtripV1) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  metadata.country = "US";
  metadata.region = "US-CA";
  metadata.city = "SUNNYVALE";
  metadata.debug_mode = 0;
  // Round to the next 15-minute cutoff.
  uint64_t seconds = absl::ToUnixSeconds(absl::Now() + absl::Minutes(15));
  seconds -= (seconds % 900);
  metadata.expiration_epoch_seconds = seconds;
  const auto encoded = Serialize(metadata);
  ASSERT_TRUE(encoded.ok()) << encoded.status();
  const auto decoded = Deserialize(encoded.value());
  ASSERT_TRUE(decoded.ok()) << decoded.status();
  EXPECT_EQ(metadata.version, decoded.value().version);
  EXPECT_EQ(metadata.service_type, decoded.value().service_type);
  EXPECT_EQ(metadata.country, decoded.value().country);
  EXPECT_EQ(metadata.region, decoded.value().region);
  EXPECT_EQ(metadata.city, decoded.value().city);
  EXPECT_EQ(metadata.debug_mode, decoded.value().debug_mode);
  EXPECT_EQ(metadata.expiration_epoch_seconds,
            decoded.value().expiration_epoch_seconds);
}

TEST(BinaryPublicMetadataSerialize, RoundtripV2) {
  BinaryPublicMetadata metadata;
  metadata.version = 2;
  metadata.service_type = "chromeipblinding";
  metadata.country = "US";
  metadata.region = "US-CA";
  metadata.city = "SUNNYVALE";
  metadata.proxy_layer = 1;
  metadata.debug_mode = 0;
  // Round to the next 15-minute cutoff.
  uint64_t seconds = absl::ToUnixSeconds(absl::Now() + absl::Minutes(15));
  seconds -= (seconds % 900);
  metadata.expiration_epoch_seconds = seconds;
  const auto encoded = Serialize(metadata);
  ASSERT_TRUE(encoded.ok()) << encoded.status();
  const auto decoded = Deserialize(encoded.value());
  ASSERT_TRUE(decoded.ok()) << decoded.status();
  EXPECT_EQ(metadata.version, decoded.value().version);
  EXPECT_EQ(metadata.service_type, decoded.value().service_type);
  EXPECT_EQ(metadata.country, decoded.value().country);
  EXPECT_EQ(metadata.region, decoded.value().region);
  EXPECT_EQ(metadata.city, decoded.value().city);
  EXPECT_EQ(metadata.debug_mode, decoded.value().debug_mode);
  EXPECT_EQ(metadata.proxy_layer, decoded.value().proxy_layer);
  EXPECT_EQ(metadata.expiration_epoch_seconds,
            decoded.value().expiration_epoch_seconds);
}

}  // namespace
}  // namespace privacy::ppn
