// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/utils/time_util.h"

#include "google/protobuf/timestamp.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

using ::testing::EqualsProto;
using ::testing::status::IsOkAndHolds;

TEST(Time, TestDurationToProto) {
  google::protobuf::Duration proto;
  EXPECT_OK(ToProtoDuration(absl::Seconds(42), &proto));
  EXPECT_THAT(proto, EqualsProto(R"pb(
                seconds: 42 nanos: 0
              )pb"));

  EXPECT_OK(ToProtoDuration(absl::Milliseconds(43044), &proto));
  EXPECT_THAT(proto, EqualsProto(R"pb(
                seconds: 43 nanos: 44000000
              )pb"));

  EXPECT_OK(ToProtoDuration(absl::Nanoseconds(45046047048), &proto));
  EXPECT_THAT(proto, EqualsProto(R"pb(
                seconds: 45 nanos: 46047048
              )pb"));
}

TEST(Time, TestTimestampToProto) {
  google::protobuf::Timestamp proto;
  EXPECT_OK(ToProtoTime(absl::FromUnixSeconds(1596762373), &proto));
  EXPECT_THAT(proto, EqualsProto(R"pb(
                seconds: 1596762373 nanos: 0
              )pb"));

  EXPECT_OK(ToProtoTime(absl::FromUnixMillis(1596762373123L), &proto));
  EXPECT_THAT(proto, EqualsProto(R"pb(
                seconds: 1596762373 nanos: 123000000
              )pb"));
}

TEST(Time, TestParseTimestamp) {
  EXPECT_THAT(ParseTimestamp("2020-08-07T01:06:13+00:00"),
              IsOkAndHolds(absl::FromUnixSeconds(1596762373)));
}

TEST(Time, TestTimeFromProto) {
  // Time used maps to: 2020-02-13T11:31:30+00:00".
  google::protobuf::Timestamp timestamp;
  timestamp.set_seconds(1234567890);
  timestamp.set_nanos(12345);
  absl::StatusOr<absl::Time> time = TimeFromProto(timestamp);
  ASSERT_OK(time);
  ASSERT_EQ(time.value(), absl::FromUnixNanos(1234567890000012345));
}

}  // namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
