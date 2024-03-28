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

#include <optional>
#include <string>

#include "privacy/net/common/proto/ppn_status.proto.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/cord.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace utils {

namespace {

absl::Status CreateDisallowedCountryStatus(absl::string_view message) {
  absl::Status status = absl::FailedPreconditionError(message);
  ppn::PpnStatusDetails details;
  details.set_detailed_error_code(ppn::PpnStatusDetails::DISALLOWED_COUNTRY);
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
      // countries. Since these backends do not attach a PpnStatusDetails to the
      // response we need to create one, until we stop using Zinc and Brass.
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

absl::Status GetStatusForHttpResponse(
    const HttpResponse& http_response,
    std::optional<absl::string_view> alternate_message) {
  std::string message = http_response.status().message();
  if (alternate_message.has_value()) {
    message = std::string(*alternate_message);
  }
  absl::Status status =
      GetStatusForHttpStatus(http_response.status().code(), message);
  if (!status.ok() && http_response.has_proto_body()) {
    ppn::PpnStatusDetails status_details;
    if (status_details.ParseFromString(http_response.proto_body())) {
      SetPpnStatusDetails(&status, status_details);
    }
  }
  return status;
}

bool IsPermanentError(absl::Status status) {
  if (status.code() == absl::StatusCode::kPermissionDenied) {
    return true;
  }

  if (status.code() == absl::StatusCode::kFailedPrecondition) {
    switch (GetPpnStatusDetails(status).detailed_error_code()) {
      case ppn::PpnStatusDetails::DISALLOWED_COUNTRY:
      case ppn::PpnStatusDetails::LIBRARY_NOT_FOUND:
      case ppn::PpnStatusDetails::OASIS_DISABLED:
        return true;
      default:
        return false;
    }
  }

  return false;
}

ppn::PpnStatusDetails GetPpnStatusDetails(absl::Status status) {
  ppn::PpnStatusDetails details;
  std::optional<absl::Cord> payload =
      status.GetPayload(kPpnStatusDetailsPayloadKey);
  if (payload.has_value()) {
    std::string s;
    absl::CopyCordToString(*payload, &s);
    details.ParseFromString(s);
  }
  return details;
}

void SetPpnStatusDetails(absl::Status* status, ppn::PpnStatusDetails details) {
  status->SetPayload(kPpnStatusDetailsPayloadKey,
                     absl::Cord(details.SerializeAsString()));
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
