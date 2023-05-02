#include "privacy/net/common/cpp/public_metadata/fingerprint.h"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/any.proto.h"
#include "google/protobuf/timestamp.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/functional/function_ref.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy::ppn {
namespace {

TEST(FingerprintPublicMetadataTest, OmitEmptyFields) {
  // Ensure that FingerprintPublicMetadata doesn't change values when new fields
  // are added.
  uint64_t cmp = 14425702572122860291u;
  uint64_t default_instance_fingerprint = 0;
  ASSERT_OK(FingerprintPublicMetadata(PublicMetadata::default_instance(),
                                      &default_instance_fingerprint));
  EXPECT_EQ(default_instance_fingerprint, cmp);

  PublicMetadata with_default_values;
  with_default_values.mutable_exit_location()->set_country("");
  with_default_values.mutable_exit_location()->set_city_geo_id("");
  with_default_values.set_service_type("");
  with_default_values.mutable_expiration()->set_seconds(0);
  with_default_values.mutable_expiration()->set_nanos(0);
  with_default_values.set_debug_mode(PublicMetadata::UNSPECIFIED_DEBUG_MODE);
  uint64_t default_value_fingerprint = 0;
  ASSERT_OK(FingerprintPublicMetadata(with_default_values,
                                      &default_value_fingerprint));
  EXPECT_EQ(default_value_fingerprint, default_instance_fingerprint);
}

TEST(FingerprintPublicMetadataTest, DoesNotNarrow) {
  // Ensure that FingerprintPublicMetadata doesn't narrow integral fields to 32
  // bits.
  int64_t larger_than_i32 = std::numeric_limits<int32_t>::max() + 1L;
  PublicMetadata metadata1;
  metadata1.mutable_expiration()->set_seconds(larger_than_i32);
  PublicMetadata metadata2;
  metadata2.mutable_expiration()->set_seconds(
      static_cast<int32_t>(larger_than_i32));
  uint64_t fingerprint1 = 0;
  ASSERT_OK(FingerprintPublicMetadata(metadata1, &fingerprint1));
  uint64_t fingerprint2 = 0;
  ASSERT_OK(FingerprintPublicMetadata(metadata2, &fingerprint2));
  EXPECT_NE(fingerprint1, fingerprint2);
}

TEST(FingerprintPublicMetadataTest, ChangeDetector) {
  // This is a change detector test to ensure that the fingerprint remains
  // stable over time. Be very wary of any changes that update existing
  // assertions.
  PublicMetadata metadata;
  metadata.mutable_exit_location()->set_country("US");
  metadata.mutable_exit_location()->set_city_geo_id("us_ca_mountain_view");
  metadata.set_service_type("g1");
  metadata.mutable_expiration()->set_seconds(123);
  metadata.mutable_expiration()->set_nanos(456);
  metadata.set_debug_mode(PublicMetadata::DEBUG_ALL);
  uint64_t metadata_fingerprint = 0;
  ASSERT_OK(FingerprintPublicMetadata(metadata, &metadata_fingerprint));
  EXPECT_EQ(metadata_fingerprint, 17430318200230452452ULL);
  // When new fields are added, feel free to expand this test by setting
  // those fields and adding another assertion below the existing ones.
}

// The following tests serve to warn implementors about potential pitfalls in
// canonical fingerprinting of protobufs.
template <typename T>
class MessageTypeIsCanonicalizableTest : public ::testing::Test {};
TYPED_TEST_SUITE(MessageTypeIsCanonicalizableTest,
                 ::testing::Types<PublicMetadata>);

void FindFieldPathsMatchingPredicate(
    absl::FunctionRef<bool(const proto2::FieldDescriptor*)> predicate,
    const proto2::Descriptor* descriptor,
    std::vector<std::string>* field_paths_out,
    absl::string_view current_path = "") {
  for (int i = 0; i < descriptor->field_count(); ++i) {
    const proto2::FieldDescriptor* field = descriptor->field(i);
    if (predicate(field)) {
      std::string path = current_path.empty()
                             ? field->name()
                             : absl::StrCat(current_path, ".", field->name());
      field_paths_out->push_back(std::move(path));
    }
    // Also recurse over embedded messages.
    const proto2::Descriptor* embedded_descriptor = field->message_type();
    if (embedded_descriptor != nullptr) {
      std::string path = current_path.empty()
                             ? field->name()
                             : absl::StrCat(current_path, ".", field->name());
      FindFieldPathsMatchingPredicate(predicate, embedded_descriptor,
                                      field_paths_out, path);
    }
  }
}

TYPED_TEST(MessageTypeIsCanonicalizableTest, FloatFieldsDisallowed) {
  // If you're reading this because you added a floating-point field to a proto
  // that should be canonically fingerprinted, then please ensure that clients
  // validate the expected precision (absl::StrCat emits six-digit precision)
  // before allowlisting that field in this test.
  TypeParam message;
  std::vector<std::string> any_field_paths;
  FindFieldPathsMatchingPredicate(
      [](const proto2::FieldDescriptor* field) {
        return field->type() == proto2::FieldDescriptor::TYPE_FLOAT ||
               field->type() == proto2::FieldDescriptor::TYPE_DOUBLE;
      },
      message.descriptor(), &any_field_paths);
  EXPECT_THAT(any_field_paths, testing::IsEmpty());
}

TYPED_TEST(MessageTypeIsCanonicalizableTest, AnyFieldsDisallowed) {
  // If you're reading this because you added a google.protobuf.Any field to a
  // proto that should be canonically fingerprinted, then please ensure that the
  // method can also deserialize and canonically fingerprint the full set of
  // types that that Any field may contain (not just their serialization) before
  // allowlisting that field in this test.
  TypeParam message;
  std::vector<std::string> any_field_paths;
  FindFieldPathsMatchingPredicate(
      [](const proto2::FieldDescriptor* field) {
        return field->message_type() == google::protobuf::Any::descriptor();
      },
      message.descriptor(), &any_field_paths);
  EXPECT_THAT(any_field_paths, testing::IsEmpty());
}

TYPED_TEST(MessageTypeIsCanonicalizableTest, MapFieldsDisallowed) {
  // If you're reading this because you added a map field to a proto that should
  // be canonically fingerprinted, then please ensure the method produces a
  // stable order for map keys before allowlisting that field this test.
  TypeParam message;
  std::vector<std::string> map_field_paths;
  FindFieldPathsMatchingPredicate(
      [](const proto2::FieldDescriptor* field) { return field->is_map(); },
      message.descriptor(), &map_field_paths);
  EXPECT_THAT(map_field_paths, testing::IsEmpty());
}

TYPED_TEST(MessageTypeIsCanonicalizableTest, DefaultValuesDisallowed) {
  // If you're reading this because you added a field with an explicit default
  // value to a proto that should be canonically fingerprinted, then please
  // ensure that the method can correctly omit that field when its value
  // matches the default before allowlisting that field in this test.
  // Note: do not change the default value of an existing field under any
  // circumstances. go/protodosdonts#dont-change-the-default-value-of-a-field
  TypeParam message;
  std::vector<std::string> explicit_default_field_paths;
  FindFieldPathsMatchingPredicate(
      [](const proto2::FieldDescriptor* field) {
        return field->has_default_value();
      },
      message.descriptor(), &explicit_default_field_paths);
  EXPECT_THAT(explicit_default_field_paths, testing::IsEmpty());
}

}  // namespace
}  // namespace privacy::ppn
