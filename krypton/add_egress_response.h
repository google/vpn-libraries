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

#ifndef PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_
#define PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_

#include <optional>

#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {

// Response for the Auth.
class AddEgressResponse {
 public:
  static absl::StatusOr<AddEgressResponse> FromProto(
      const HttpResponse& http_response) {
    AddEgressResponse response;
    PPN_RETURN_IF_ERROR(response.DecodeFromProto(http_response));
    return response;
  }

  AddEgressResponse() = default;

  absl::StatusOr<net::common::proto::PpnDataplaneResponse>
  ppn_dataplane_response() const {
    if (ppn_dataplane_response_ == std::nullopt) {
      return absl::FailedPreconditionError("No dataplane response found");
    }
    return *ppn_dataplane_response_;
  }

  absl::StatusOr<net::common::proto::PpnIkeResponse> ike_response() const {
    if (ike_response_ == std::nullopt) {
      return absl::FailedPreconditionError("No IKE response found");
    }
    return *ike_response_;
  }

 private:
  // Decodes the proto to AddEgressResponse.
  absl::Status DecodeFromProto(const HttpResponse& response);

  // Decode AddEgressResponse specific parameters
  absl::Status DecodeJsonBody(nlohmann::json json_obj);

  // PPN data plane response.
  std::optional<net::common::proto::PpnDataplaneResponse>
      ppn_dataplane_response_;

  // IKE response.
  std::optional<net::common::proto::PpnIkeResponse> ike_response_;

  absl::Status parsing_status_ =
      absl::UnknownError("Initialized, no parsing status set");
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_
