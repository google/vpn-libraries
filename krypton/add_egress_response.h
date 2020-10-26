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

#ifndef PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_
#define PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_

#include <memory>
#include <string>
#include <vector>

#include "privacy/net/krypton/http_header.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

class BridgeDataPlaneResponse;
class PpnDataPlaneResponse;

// Response for the Auth.
class AddEgressResponse {
 public:
  AddEgressResponse() = default;
  ~AddEgressResponse() = default;

  // Decodes the string to AuthAndSignResponse.
  absl::Status DecodeFromJsonObject(absl::string_view json_string);

  absl::Status parsing_status() const { return parsing_status_; }

  const HttpResponse& http_response() const { return http_response_; }

  absl::StatusOr<BridgeDataPlaneResponse*> bridge_dataplane_response() const {
    if (bridge_dataplane_response_ == nullptr) {
      return absl::FailedPreconditionError(
          "No Bridge dataplane response found");
    }
    return bridge_dataplane_response_.get();
  }

  absl::StatusOr<PpnDataPlaneResponse*> ppn_dataplane_response() const {
    if (ppn_dataplane_response_ == nullptr) {
      return absl::FailedPreconditionError(
          "No Bridge dataplane response found");
    }

    return ppn_dataplane_response_.get();
  }

  // returns if the Egress if for PPNDataplane
  bool is_ppn() const { return ppn_dataplane_response_ != nullptr; }

 private:
  HttpResponse http_response_;
  // DecodeFromJsonObject AddEgressResponse specific parameters
  absl::Status DecodeJsonBody(Json::Value value);
  // Bridge data plane response.
  std::unique_ptr<BridgeDataPlaneResponse> bridge_dataplane_response_;
  // PPN data plane response.
  std::unique_ptr<PpnDataPlaneResponse> ppn_dataplane_response_;
  absl::Status parsing_status_ =
      absl::UnknownError("Initialized, no parsing status set");
  // TODO: Store session parameters like User IP and egress node
  // details as rekey response will not contain them.
};

// Container for storing BridgeDataPlaneResponse.  The data is not parsed to
// local memory and kept as Json.  This class needs to be removed once the IPSec
// integration is complete.
class BridgeDataPlaneResponse {
 public:
  explicit BridgeDataPlaneResponse(Json::Value response_json);
  ~BridgeDataPlaneResponse() = default;

  absl::StatusOr<uint64> GetSessionId() const;
  absl::StatusOr<std::string> GetSessionToken() const;
  absl::StatusOr<std::string> GetClientCryptoKey() const;
  absl::StatusOr<std::string> GetServerCryptoKey() const;
  absl::StatusOr<std::vector<std::string>> GetIpRanges() const;
  absl::StatusOr<std::vector<std::string>> GetDataplaneSockAddresses() const;
  absl::StatusOr<std::vector<std::string>> GetControlPlaneSockAddresses() const;
  absl::StatusOr<std::string> GetError() const;

 private:
  Json::Value bridge_data_plane_response_json_;
};

class PpnDataPlaneResponse {
 public:
  explicit PpnDataPlaneResponse(Json::Value ppn_json);
  ~PpnDataPlaneResponse() = default;

  absl::StatusOr<std::vector<std::string>> GetUserPrivateIp() const;
  absl::StatusOr<std::vector<std::string>> GetEgressPointSockAddr() const;
  absl::StatusOr<std::string> GetEgressPointPublicKey() const;
  absl::StatusOr<std::string> GetServerNonce() const;
  absl::StatusOr<uint32> GetUplinkSpi() const;
  absl::StatusOr<absl::Time> GetExpiry() const;

 private:
  Json::Value ppn_data_plane_response_json_;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_ADD_EGRESS_RESPONSE_H_
