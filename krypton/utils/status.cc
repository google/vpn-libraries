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

#include <string>

#include "privacy/net/krypton/proto/ppn_status.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/cord.h"

namespace privacy {
namespace krypton {
namespace utils {

namespace {

absl::Status CreateDisallowedCountryStatus(absl::string_view message) {
  absl::Status status = absl::FailedPreconditionError(message);
  PpnStatusDetails details;
  details.set_detailed_error_code(PpnStatusDetails::DISALLOWED_COUNTRY);
  SetPpnStatusDetails(&status, details);
  return status;
}

}  // namespace

constexpr char kPpnStatusDetailsPayloadKey[] = "privacy.google.com/ppn.status";

absl::Status GetStatusForHttpStatus(int http_status,
                                    absl::string_view message) {
  switch (http_status) {
    case 200:
      return absl::OkStatus();
    case 400:
      return absl::InvalidArgumentError(message);
    case 401:
      return absl::UnauthenticatedError(message);
    case 403:
      return absl::PermissionDeniedError(message);
    case 404:
      return absl::NotFoundError(message);
    case 409:
      return absl::AbortedError(message);
    case 412:
      // The zinc and brass backends specifically reserve 412 for disallowed
      // countries, so attach a detailed error code so that we can handle this
      // with a special UI and treat it as a permanent error.
      return CreateDisallowedCountryStatus(message);
    case 429:
      return absl::ResourceExhaustedError(message);
    case 499:
      return absl::CancelledError(message);
    case 500:
      return absl::InternalError(message);
    case 501:
      return absl::UnimplementedError(message);
    case 503:
      return absl::UnavailableError(message);
    case 504:
      return absl::DeadlineExceededError(message);
  }
  if (http_status >= 200 && http_status < 300) {
    return absl::OkStatus();
  }
  if (http_status >= 400 && http_status < 500) {
    return absl::FailedPreconditionError(message);
  }
  if (http_status >= 500 && http_status < 600) {
    return absl::InternalError(message);
  }
  return absl::UnknownError(message);
}

// TODO: Finalize all permanent status code values.
bool IsPermanentError(absl::Status status) {
  if (status.code() == absl::StatusCode::kPermissionDenied) {
    return true;
  }

  if (status.code() == absl::StatusCode::kFailedPrecondition &&
      GetPpnStatusDetails(status).detailed_error_code() ==
          PpnStatusDetails::DISALLOWED_COUNTRY) {
    return true;
  }

  return false;
}

PpnStatusDetails GetPpnStatusDetails(absl::Status status) {
  PpnStatusDetails details;
  auto payload = status.GetPayload(kPpnStatusDetailsPayloadKey);
  if (payload) {
    std::string s;
    absl::CopyCordToString(*payload, &s);
    details.ParseFromString(s);
  }
  return details;
}

void SetPpnStatusDetails(absl::Status* status, PpnStatusDetails details) {
  status->SetPayload(kPpnStatusDetailsPayloadKey,
                     absl::Cord(details.SerializeAsString()));
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
