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

#include "privacy/net/krypton/egress_manager.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/utils/ip_range.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "privacy/net/krypton/utils/time_util.h"
#include "third_party/absl/functional/bind_front.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/time/clock.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace {

const uint32 kLatencyCollectionLimit = 5;

std::string StateString(EgressManager::State state) {
  switch (state) {
    case EgressManager::State::kEgressSessionError:
      return "kEgressSessionError";

    case EgressManager::State::kEgressSessionCreated:
      return "kEgressSessionCreated";

    case EgressManager::State::kInitialized:
      return "kInitialized";
  }
  return std::string();
}
}  // namespace

EgressManager::EgressManager(absl::string_view brass_url,
                             HttpFetcherInterface* http_fetcher,
                             utils::LooperThread* notification_thread)
    : http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)),
      notification_thread_(notification_thread),
      brass_url_(brass_url),
      state_(State::kInitialized) {}

EgressManager::~EgressManager() {
  absl::MutexLock l(&mutex_);
  if (!stopped_) {
    LOG(DFATAL) << " Please call stop before deleting EgressManager";
  }
}

void EgressManager::Stop() {
  absl::MutexLock l(&mutex_);
  LOG(INFO) << "Egress manager Stop";
  stopped_ = true;
  http_fetcher_.CancelAsync();
}

absl::StatusOr<std::shared_ptr<AddEgressResponse>>
EgressManager::GetEgressSessionDetails() const {
  absl::MutexLock lock(&mutex_);
  if (egress_node_response_ == nullptr) {
    return absl::NotFoundError("No Egress response found");
  }
  return egress_node_response_;
}

void EgressManager::SetState(State state) {
  LOG(INFO) << "Transitioning from " << StateString(state_) << " to "
            << StateString(state);
  state_ = state;
  if (notification_ == nullptr) {
    LOG(ERROR) << "Notification is null to notify state change event";
  }
  switch (state) {
    case State::kEgressSessionError: {
      NotificationInterface* notification = notification_;
      auto status = latest_status_;
      notification_thread_->Post(
          [notification, status] { notification->EgressUnavailable(status); });

      break;
    }
    case State::kEgressSessionCreated:
    case State::kInitialized:
      break;
  }
}

absl::Status EgressManager::SaveEgressDetails(
    std::shared_ptr<AddEgressResponse> egress_response) {
  // Store the key parameters for the response.  Response could be Bridge or
  // PPN.

  // For PPN:
  auto status_or_ppn_data_plane_response =
      egress_response->ppn_dataplane_response();
  if (status_or_ppn_data_plane_response.ok()) {
    is_ppn_ = true;
    PPN_ASSIGN_OR_RETURN(
        uplink_spi_, status_or_ppn_data_plane_response.value()->GetUplinkSpi());
    PPN_ASSIGN_OR_RETURN(
        auto egress_nodes,
        status_or_ppn_data_plane_response.value()->GetEgressPointSockAddr());
    std::copy(egress_nodes.begin(), egress_nodes.end(),
              std::back_inserter(egress_node_sock_addresses_));
  }

  // For Bridge
  auto status_or_bridge_response = egress_response->bridge_dataplane_response();
  if (status_or_bridge_response.ok()) {
    is_ppn_ = false;
    PPN_ASSIGN_OR_RETURN(uplink_spi_,
                         status_or_bridge_response.value()->GetSessionId());
    LOG(INFO) << "Session Id " << uplink_spi_;
    PPN_ASSIGN_OR_RETURN(
        auto egress_nodes,
        status_or_bridge_response.value()->GetDataplaneSockAddresses());
    std::copy(egress_nodes.begin(), egress_nodes.end(),
              std::back_inserter(egress_node_sock_addresses_));
  }
  return absl::OkStatus();
}

void EgressManager::DecodeAddEgressResponse(
    bool is_rekey, const std::string& string_response) {
  absl::MutexLock l(&mutex_);
  google::protobuf::Duration latency;
  if (!utils::ToProtoDuration(absl::Now() - request_time_, &latency).ok()) {
    LOG(ERROR) << "Unable to calculate latency.";
  } else {
    if (latencies_.size() < kLatencyCollectionLimit) {
      latencies_.emplace_back(latency);
    } else {
      LOG(ERROR) << "Max latency collection limit reached, not adding latency:"
                 << absl::Now() - request_time_;
    }
  }

  request_time_ = ::absl::InfinitePast();

  LOG(INFO) << "Got AddEgressResponse";
  if (stopped_) {
    LOG(ERROR) << "EgressManager is already cancelled, don't update";
    return;
  }

  auto add_egress_response = std::make_shared<AddEgressResponse>();

  latest_status_ = add_egress_response->DecodeFromJsonObject(string_response);

  if (!latest_status_.ok()) {
    SetState(State::kEgressSessionError);
    LOG(ERROR) << "Error decoding AddEgressResponse";
    return;
  }
  if (egress_node_response_ != nullptr) {
    LOG(INFO) << "Overwriting AddEgressResponse";
    egress_node_response_.reset();
  }
  egress_node_response_ = std::move(add_egress_response);

  int http_status = egress_node_response_->http_response().status();
  if (http_status == 200) {
    SetState(State::kEgressSessionCreated);
    // Save the parameters only if it's not Rekey.
    if (!is_rekey) {
      auto save_status = SaveEgressDetails(egress_node_response_);
      if (!save_status.ok()) {
        LOG(ERROR) << "Saving egress details failed with status "
                   << save_status;
      }
    }
    NotificationInterface* notification = notification_;
    notification_thread_->Post(
        [notification, is_rekey] { notification->EgressAvailable(is_rekey); });

  } else {
    latest_status_ =
        absl::Status(utils::GetStatusCodeForHttpStatus(http_status),
                     absl::StrCat("AddEgressRequest failed with code ",
                                  http_status, "Content obfuscated"));
    SetState(State::kEgressSessionError);
  }
}

// Gets an egress node based on the auth response parameter.
absl::Status EgressManager::GetEgressNodeForBridge(
    std::shared_ptr<AuthAndSignResponse> auth_response) {
  DCHECK(notification_);
  absl::MutexLock l(&mutex_);
  request_time_ = absl::Now();
  AddEgressRequest add_egress_request;
  auto add_egress_json =
      add_egress_request.EncodeToJsonObjectForBridge(std::move(auth_response));
  if (!add_egress_json) {
    LOG(ERROR) << "Cannot build AddEgressRequest";
    return absl::FailedPreconditionError("Cannot build AddEgressRequest");
  }

  http_fetcher_.PostJsonAsync(
      brass_url_, add_egress_json.value().http_headers,
      add_egress_json.value().json_body,
      absl::bind_front(&EgressManager::DecodeAddEgressResponse, this, false));

  return absl::OkStatus();
}

absl::Status EgressManager::GetEgressNodeForPpnIpSec(
    const AddEgressRequest::PpnDataplaneRequestParams& params) {
  absl::MutexLock l(&mutex_);

  DCHECK(notification_);
  AddEgressRequest add_egress_request;
  absl::optional<uint32> uplink_spi;
  request_time_ = absl::Now();

  if (egress_node_response_ != nullptr &&
      egress_node_response_->ppn_dataplane_response().ok()) {
    auto status_or_spi =
        egress_node_response_->ppn_dataplane_response().value()->GetUplinkSpi();
    if (status_or_spi.ok()) {
      uplink_spi = status_or_spi.value();
    }
  }
  auto add_egress_json = add_egress_request.EncodeToJsonObjectForPpn(params);
  if (!add_egress_json) {
    LOG(ERROR) << "Cannot build AddEgressRequest for PPN IpSec";
    return absl::FailedPreconditionError(
        "Cannot build AddEgressRequest for PPN IPSec");
  }

  Json::FastWriter writer;

  http_fetcher_.PostJsonAsync(
      brass_url_, add_egress_json.value().http_headers,
      add_egress_json.value().json_body,
      absl::bind_front(&EgressManager::DecodeAddEgressResponse, this,
                       params.is_rekey));

  return absl::OkStatus();
}

void EgressManager::CollectTelemetry(KryptonTelemetry* telemetry) {
  absl::MutexLock l(&mutex_);
  for (const auto& latency : latencies_) {
    *telemetry->add_egress_latency() = latency;
  }
  latencies_.clear();
}

void EgressManager::GetDebugInfo(EgressDebugInfo* debug_info) {
  absl::MutexLock l(&mutex_);
  debug_info->set_state(StateString(state_));
  debug_info->set_status(latest_status_.ToString());
  for (const auto& latency : latencies_) {
    *debug_info->add_latency() = latency;
  }
}

absl::optional<std::string> EgressManager::EgressNodeV4SocketAddress() const
    ABSL_LOCKS_EXCLUDED(mutex_) {
  absl::MutexLock l(&mutex_);
  if (egress_node_sock_addresses_.empty()) {
    return absl::nullopt;
  }
  for (const auto& ip : egress_node_sock_addresses_) {
    if (utils::IsValidV4Address(ip)) {
      return ip;
    }
  }
  return absl::nullopt;
}

absl::optional<std::string> EgressManager::EgressNodeV6SocketAddress() const
    ABSL_LOCKS_EXCLUDED(mutex_) {
  absl::MutexLock l(&mutex_);
  if (egress_node_sock_addresses_.empty()) {
    return absl::nullopt;
  }
  for (const auto& ip : egress_node_sock_addresses_) {
    if (utils::IsValidV6Address(ip)) {
      return ip;
    }
  }
  return absl::nullopt;
}

}  // namespace krypton
}  // namespace privacy
