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

#include "privacy/net/krypton/utils/status.h"

#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/common/proto/ppn_status.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

using absl::StatusCode;
using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::EqualsProto;
using ::testing::status::StatusIs;

StatusCode GetStatusCodeForHttpStatus(int code) {
  return GetStatusForHttpStatus(code, "").code();
}

class StatusTest : public ::testing::Test {};

TEST_F(StatusTest, GetStatusCodeForHttpStatus) {
  EXPECT_EQ(StatusCode::kOk, GetStatusCodeForHttpStatus(200));
  EXPECT_EQ(StatusCode::kOk, GetStatusCodeForHttpStatus(201));
  EXPECT_EQ(StatusCode::kInvalidArgument, GetStatusCodeForHttpStatus(400));
  EXPECT_EQ(StatusCode::kUnauthenticated, GetStatusCodeForHttpStatus(401));
  EXPECT_EQ(StatusCode::kPermissionDenied, GetStatusCodeForHttpStatus(403));
  EXPECT_EQ(StatusCode::kNotFound, GetStatusCodeForHttpStatus(404));
  EXPECT_EQ(StatusCode::kAborted, GetStatusCodeForHttpStatus(409));
  EXPECT_EQ(StatusCode::kFailedPrecondition, GetStatusCodeForHttpStatus(412));
  EXPECT_EQ(StatusCode::kResourceExhausted, GetStatusCodeForHttpStatus(429));
  EXPECT_EQ(StatusCode::kCancelled, GetStatusCodeForHttpStatus(499));
  EXPECT_EQ(StatusCode::kInternal, GetStatusCodeForHttpStatus(500));
  EXPECT_EQ(StatusCode::kUnimplemented, GetStatusCodeForHttpStatus(501));
  EXPECT_EQ(StatusCode::kUnavailable, GetStatusCodeForHttpStatus(503));
  EXPECT_EQ(StatusCode::kDeadlineExceeded, GetStatusCodeForHttpStatus(504));
  EXPECT_EQ(StatusCode::kInternal, GetStatusCodeForHttpStatus(505));
  EXPECT_EQ(StatusCode::kUnknown, GetStatusCodeForHttpStatus(600));
}

TEST_F(StatusTest, TestPermanentFailures) {
  EXPECT_TRUE(IsPermanentError(absl::PermissionDeniedError("")));
  EXPECT_FALSE(IsPermanentError(absl::InvalidArgumentError("")));
  EXPECT_FALSE(IsPermanentError(absl::UnauthenticatedError("")));
  EXPECT_FALSE(IsPermanentError(absl::NotFoundError("")));
  EXPECT_FALSE(IsPermanentError(absl::AbortedError("")));
  EXPECT_FALSE(IsPermanentError(absl::FailedPreconditionError("")));
  EXPECT_FALSE(IsPermanentError(absl::ResourceExhaustedError("")));
  EXPECT_FALSE(IsPermanentError(absl::CancelledError("")));
  EXPECT_FALSE(IsPermanentError(absl::InternalError("")));
  EXPECT_FALSE(IsPermanentError(absl::UnimplementedError("")));
  EXPECT_FALSE(IsPermanentError(absl::UnavailableError("")));
  EXPECT_FALSE(IsPermanentError(absl::DeadlineExceededError("")));
}

TEST_F(StatusTest, TestPpnStatusDetailsDefault) {
  auto status = absl::FailedPreconditionError("error");
  ppn::PpnStatusDetails details = GetPpnStatusDetails(status);
  EXPECT_EQ(ppn::PpnStatusDetails::ERROR_CODE_UNKNOWN,
            details.detailed_error_code());
}

TEST_F(StatusTest, TestPpnStatusDetails) {
  ppn::PpnStatusDetails input;
  input.set_detailed_error_code(ppn::PpnStatusDetails::DISALLOWED_COUNTRY);
  auto status = absl::FailedPreconditionError("error");
  SetPpnStatusDetails(&status, input);

  ppn::PpnStatusDetails details = GetPpnStatusDetails(status);
  EXPECT_EQ(ppn::PpnStatusDetails::DISALLOWED_COUNTRY,
            details.detailed_error_code());
}

TEST_F(StatusTest, TestHttpStatus412) {
  absl::Status status = GetStatusForHttpStatus(412, "disallowed country");
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, status.code());
  EXPECT_EQ("disallowed country", status.message());

  ppn::PpnStatusDetails details = GetPpnStatusDetails(status);
  EXPECT_EQ(ppn::PpnStatusDetails::DISALLOWED_COUNTRY,
            details.detailed_error_code());

  EXPECT_TRUE(IsPermanentError(status));
}

TEST_F(StatusTest,
       GetStatusForHttpResponseWithDisallowedCountryIncludesPpnStatus) {
  ppn::PpnStatusDetails details;
  details.set_detailed_error_code(ppn::PpnStatusDetails::DISALLOWED_COUNTRY);
  HttpResponse http_response;
  http_response.mutable_status()->set_code(412);
  http_response.mutable_status()->set_message("disallowed country");
  http_response.set_proto_body(details.SerializeAsString());

  absl::Status status = GetStatusForHttpResponse(http_response);

  EXPECT_THAT(status, StatusIs(absl::StatusCode::kFailedPrecondition,
                               "disallowed country"));
  EXPECT_THAT(GetPpnStatusDetails(status), EqualsProto(details));
}

TEST_F(StatusTest, GetStatusForHttpResponseWithOasisDisabledIncludesPpnStatus) {
  ppn::PpnStatusDetails details;
  details.set_detailed_error_code(ppn::PpnStatusDetails::OASIS_DISABLED);
  HttpResponse http_response;
  http_response.mutable_status()->set_code(412);
  http_response.mutable_status()->set_message("oasis disabled");
  http_response.set_proto_body(details.SerializeAsString());

  absl::Status status = GetStatusForHttpResponse(http_response);

  EXPECT_THAT(status, StatusIs(absl::StatusCode::kFailedPrecondition,
                               "oasis disabled"));
  EXPECT_THAT(GetPpnStatusDetails(status), EqualsProto(details));
}

TEST_F(StatusTest, GetStatusForHttpResponseIgnoresInvalidProtobuf) {
  HttpResponse http_response;
  http_response.mutable_status()->set_code(418);
  http_response.mutable_status()->set_message("failure");
  http_response.set_proto_body("invalid");

  absl::Status status = GetStatusForHttpResponse(http_response);

  EXPECT_THAT(GetPpnStatusDetails(status),
              EqualsProto(R"pb(detailed_error_code: 0
                               auth_internal_error_code: 0)pb"));
}

TEST_F(StatusTest, GetStatusForHttpResponseIgnoresInvalidPpnStatusDetails) {
  ppn::PpnStatusDetails details =
      ParseTextProtoOrDie(R"pb(detailed_error_code: 999,
                               auth_internal_error_code: 12)pb");
  HttpResponse http_response;
  http_response.mutable_status()->set_code(418);
  http_response.mutable_status()->set_message("failure");
  http_response.set_proto_body(details.SerializeAsString());

  absl::Status status = GetStatusForHttpResponse(http_response);

  EXPECT_THAT(GetPpnStatusDetails(status),
              EqualsProto(R"pb(detailed_error_code: 0
                               auth_internal_error_code: 0)pb"));
}

}  // anonymous namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
