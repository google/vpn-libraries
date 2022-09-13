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

#ifndef PRIVACY_NET_KRYPTON_UTILS_STATUS_H_
#define PRIVACY_NET_KRYPTON_UTILS_STATUS_H_

#include <utility>

#include "privacy/net/krypton/proto/ppn_status.proto.h"
#include "third_party/absl/base/optimization.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace utils {

#define PPN_RETURN_IF_ERROR(expr)                          \
  do {                                                     \
    auto _status = (expr);                                 \
    if (ABSL_PREDICT_FALSE(!_status.ok())) return _status; \
  } while (0)

#define PPN_LOG_IF_ERROR(expr)               \
  do {                                       \
    auto _status = (expr);                   \
    if (ABSL_PREDICT_FALSE(!_status.ok())) { \
      LOG(ERROR) << _status;                 \
    }                                        \
  } while (0)

#define _PPN_STATUS_MACROS_CONCAT_NAME(x, y) \
  _PPN_STATUS_MACROS_CONCAT_IMPL(x, y)
#define _PPN_STATUS_MACROS_CONCAT_IMPL(x, y) x##y

#define PPN_ASSIGN_OR_RETURN(lhs, rexpr) \
  _PPN_ASSIGN_OR_RETURN_IMPL(            \
      _PPN_STATUS_MACROS_CONCAT_NAME(_status_or_val, __LINE__), lhs, rexpr)

#define _PPN_ASSIGN_OR_RETURN_IMPL(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                               \
  if (ABSL_PREDICT_FALSE(!statusor.ok())) {              \
    return statusor.status();                            \
  }                                                      \
  lhs = std::move(statusor.ValueOrDie())

// Takes an HTTP status code and returns the corresponding absl::Status.
// This uses the standard HTTP status code -> error mapping defined in:
// https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
absl::Status GetStatusForHttpStatus(int http_status, absl::string_view message);

// Status code errors that are treated as permanent errors.
bool IsPermanentError(absl::Status status);

/** Gets PPN-specific details from the given Status. */
PpnStatusDetails GetPpnStatusDetails(absl::Status status);

/** Attaches PPN-specific detailts to the given Status. */
void SetPpnStatusDetails(absl::Status* status, PpnStatusDetails details);

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_STATUS_H_
