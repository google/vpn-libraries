/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/windows/utils/error.h"

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/internal/status_internal.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace utils {
namespace {

using testing::HasSubstr;
using testing::status::StatusIs;

TEST(ErrorTest, BasicTest) {
  EXPECT_THAT(GetStatusForError("foo", ERROR_INVALID_FLAGS),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("foo: Error 0x000003ec: Invalid flags")));
}

TEST(ErrorTest, EmptyPrefixTest) {
  EXPECT_THAT(
      GetStatusForError("", ERROR_INVALID_FLAGS),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("Invalid flags.")));
}

TEST(ErrorTest, NotFoundTest) {
  EXPECT_THAT(GetStatusForError("foo", ERROR_NOT_FOUND),
              StatusIs(absl::StatusCode::kNotFound,
                       HasSubstr("foo: Error 0x00000490: Element not found.")));
}

TEST(ErrorTest, WSATest) {
  EXPECT_THAT(
      GetStatusForError("foo", WSANOTINITIALISED),
      StatusIs(absl::StatusCode::kInternal,
               testing::AllOf(
                   testing::HasSubstr("foo"),
                   testing::HasSubstr("Either the application has not called "
                                      "WSAStartup, or WSAStartup failed"))));
}

TEST(GetRpcStatusforStatusTest, BasicTest) {
  absl::Status status = absl::InternalError("Failed");
  status.SetPayload("type_url", absl::Cord("payload"));
  google::rpc::Status rpc_status = GetRpcStatusforStatus(status);
  EXPECT_EQ(rpc_status.code(), google::rpc::INTERNAL);
  EXPECT_EQ(rpc_status.message(), "Failed");
  EXPECT_EQ(rpc_status.details(0).type_url(), "type_url");
  EXPECT_EQ(rpc_status.details(0).value(), "payload");
}

TEST(GetRpcStatusforStatusTest, NoPayload) {
  absl::Status status = absl::InternalError("Failed");
  google::rpc::Status rpc_status = GetRpcStatusforStatus(status);
  EXPECT_EQ(rpc_status.code(), google::rpc::INTERNAL);
  EXPECT_EQ(rpc_status.message(), "Failed");
}

}  // namespace
}  // namespace utils
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
