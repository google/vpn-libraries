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

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace utils {

absl::StatusCode GetStatusCodeForHttpStatus(int http_status) {
  switch (http_status) {
    case 200:
      return absl::StatusCode::kOk;
    case 400:
      return absl::StatusCode::kInvalidArgument;
    case 401:
      return absl::StatusCode::kUnauthenticated;
    case 403:
      return absl::StatusCode::kPermissionDenied;
    case 404:
      return absl::StatusCode::kNotFound;
    case 409:
      return absl::StatusCode::kAborted;
    case 429:
      return absl::StatusCode::kResourceExhausted;
    case 499:
      return absl::StatusCode::kCancelled;
    case 500:
      return absl::StatusCode::kInternal;
    case 501:
      return absl::StatusCode::kUnimplemented;
    case 503:
      return absl::StatusCode::kUnavailable;
    case 504:
      return absl::StatusCode::kDeadlineExceeded;
  }
  return absl::StatusCode::kUnknown;
}

// TODO: Finalize all permanent status code values.
bool IsPermanentError(absl::StatusCode code) {
  switch (code) {
    case absl::StatusCode::kPermissionDenied:
      return true;
    default:
      return false;
  }
}
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
