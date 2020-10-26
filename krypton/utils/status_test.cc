// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/utils/status.h"

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

using absl::StatusCode;

class StatusTest : public ::testing::Test {};

TEST_F(StatusTest, GetStatusCodeForHttpStatus) {
  EXPECT_THAT(GetStatusCodeForHttpStatus(200), ::testing::Eq(StatusCode::kOk));
  EXPECT_THAT(GetStatusCodeForHttpStatus(400),
              ::testing::Eq(StatusCode::kInvalidArgument));
  EXPECT_THAT(GetStatusCodeForHttpStatus(401),
              ::testing::Eq(StatusCode::kUnauthenticated));
  EXPECT_THAT(GetStatusCodeForHttpStatus(403),
              ::testing::Eq(StatusCode::kPermissionDenied));
  EXPECT_THAT(GetStatusCodeForHttpStatus(404),
              ::testing::Eq(StatusCode::kNotFound));
  EXPECT_THAT(GetStatusCodeForHttpStatus(409),
              ::testing::Eq(StatusCode::kAborted));
  EXPECT_THAT(GetStatusCodeForHttpStatus(429),
              ::testing::Eq(StatusCode::kResourceExhausted));
  EXPECT_THAT(GetStatusCodeForHttpStatus(499),
              ::testing::Eq(StatusCode::kCancelled));
  EXPECT_THAT(GetStatusCodeForHttpStatus(500),
              ::testing::Eq(StatusCode::kInternal));
  EXPECT_THAT(GetStatusCodeForHttpStatus(501),
              ::testing::Eq(StatusCode::kUnimplemented));
  EXPECT_THAT(GetStatusCodeForHttpStatus(503),
              ::testing::Eq(StatusCode::kUnavailable));
  EXPECT_THAT(GetStatusCodeForHttpStatus(504),
              ::testing::Eq(StatusCode::kDeadlineExceeded));
}

TEST_F(StatusTest, TestPermanentFailures) {
  EXPECT_TRUE(IsPermanentError(absl::StatusCode::kPermissionDenied));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kInvalidArgument));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kUnauthenticated));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kNotFound));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kAborted));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kResourceExhausted));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kCancelled));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kInternal));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kUnimplemented));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kUnavailable));
  EXPECT_FALSE(IsPermanentError(absl::StatusCode::kDeadlineExceeded));
}
}  // anonymous namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
