#include "privacy/net/common/cpp/public_metadata/public_metadata.h"

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/time/time.h"

namespace privacy::ppn {
namespace {

TEST(ValidateBinaryPublicMetadataCardinalityTest, TestGoodMetadata) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  metadata.country = "US";
  metadata.region = "US-CA";
  metadata.city = "Sunnyvale";
  // Round to the next 15-minute cutoff.
  uint64_t seconds = absl::ToUnixSeconds(absl::Now() + absl::Minutes(15));
  seconds -= (seconds % 900);
  metadata.expiration_epoch_seconds = seconds;
  EXPECT_OK(ValidateBinaryPublicMetadataCardinality(metadata, absl::Now()));
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, InvalidVersion) {
  BinaryPublicMetadata metadata;
  metadata.version = 0;
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, MissingServiceType) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, InvalidServiceType) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "spam";
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, MissingCountry) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, InvalidCountry) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  // Country is expected to be 2 characters.
  metadata.country = "USA";
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);

  // Country is expected to be all uppercase.
  metadata.country = "us";
  status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, MissingExpiration) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  metadata.country = "US";
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(ValidateBinaryPublicMetadataCardinalityTest, InvalidExpiration) {
  BinaryPublicMetadata metadata;
  metadata.version = 1;
  metadata.service_type = "chromeipblinding";
  metadata.country = "US";
  // Invalid rounding.
  uint64_t seconds = absl::ToUnixSeconds(absl::Now() + absl::Minutes(15));
  seconds -= (seconds % 900) + 1;
  metadata.expiration_epoch_seconds = seconds;
  auto status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);

  // Expiration time is in the past.
  seconds = absl::ToUnixSeconds(absl::Now() - absl::Minutes(15));
  metadata.expiration_epoch_seconds = seconds;
  status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);

  // Expiration time is too far in the future.
  seconds = absl::ToUnixSeconds(absl::Now() + absl::Hours(240));
  metadata.expiration_epoch_seconds = seconds;
  status = ValidateBinaryPublicMetadataCardinality(metadata, absl::Now());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace privacy::ppn
