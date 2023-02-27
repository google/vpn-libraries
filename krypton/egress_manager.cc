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

#include "privacy/net/krypton/egress_manager.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/logging.h"
#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/http_fetcher.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
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

namespace privacy {
namespace krypton {
namespace {

const uint32_t kLatencyCollectionLimit = 5;

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

EgressManager::EgressManager(const KryptonConfig& config,
                             HttpFetcherInterface* http_fetcher,
                             utils::LooperThread* notification_thread)
    : config_(config),
      http_fetcher_(ABSL_DIE_IF_NULL(http_fetcher),
                    ABSL_DIE_IF_NULL(notification_thread)),
      notification_thread_(notification_thread),
      brass_url_(config.brass_url()),
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

absl::StatusOr<AddEgressResponse> EgressManager::GetEgressSessionDetails()
    const {
  absl::MutexLock lock(&mutex_);
  if (egress_node_response_ == std::nullopt) {
    return absl::NotFoundError("No Egress response found");
  }
  return *egress_node_response_;
}

// TODO: Refactor egress_manager error status handling to work the same
// as the error handling in auth.cc.
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
    const AddEgressResponse& egress_response) {
  // If this is an IKE response, we don't need to save the keys here.
  if (config_.datapath_protocol() == KryptonConfig::IKE) {
    return absl::OkStatus();
  }

  // Store the key parameters for the response.
  PPN_ASSIGN_OR_RETURN(auto ppn_data_plane_response,
                       egress_response.ppn_dataplane_response());

  if (ppn_data_plane_response.uplink_spi() == 0) {
    return absl::InvalidArgumentError(
        "PPN dataplane response missing uplink SPI.");
  }
  uplink_spi_ = ppn_data_plane_response.uplink_spi();

  if (ppn_data_plane_response.egress_point_sock_addr_size() == 0) {
    return absl::InvalidArgumentError(
        "PPN dataplane response missing uplink SPI.");
  }
  auto* egress_nodes = ppn_data_plane_response.mutable_egress_point_sock_addr();
  egress_node_sock_addresses_.clear();
  std::copy(egress_nodes->begin(), egress_nodes->end(),
            std::back_inserter(egress_node_sock_addresses_));

  return absl::OkStatus();
}

void EgressManager::DecodeAddEgressResponse(bool is_rekey,
                                            const HttpResponse& http_response) {
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

  if (http_response.status().code() != 200) {
    latest_status_ = utils::GetStatusForHttpStatus(
        http_response.status().code(),
        absl::StrCat("AddEgressRequest failed with code ",
                     http_response.status().code(), ": Content obfuscated"));
    SetState(State::kEgressSessionError);
    return;
  }

  auto add_egress_response = AddEgressResponse::FromProto(http_response);

  latest_status_ = add_egress_response.status();
  if (!latest_status_.ok()) {
    SetState(State::kEgressSessionError);
    LOG(ERROR) << "Error decoding AddEgressResponse";
    return;
  }
  if (egress_node_response_ != std::nullopt) {
    LOG(INFO) << "Overwriting AddEgressResponse";
  }
  egress_node_response_ = *add_egress_response;

  SetState(State::kEgressSessionCreated);
  // Save the parameters only if it's not Rekey.
  if (!is_rekey) {
    auto save_status = SaveEgressDetails(*egress_node_response_);
    if (!save_status.ok()) {
      LOG(ERROR) << "Saving egress details failed with status " << save_status;
    }
  }
  NotificationInterface* notification = notification_;
  notification_thread_->Post(
      [notification, is_rekey] { notification->EgressAvailable(is_rekey); });
}

absl::Status EgressManager::GetEgressNodeForPpnIpSec(
    const AddEgressRequest::PpnDataplaneRequestParams& params) {
  absl::MutexLock l(&mutex_);

  DCHECK(notification_);
  auto api_key = config_.has_api_key()
                     ? std::optional<std::string>(config_.api_key())
                     : std::nullopt;
  AddEgressRequest add_egress_request(
      api_key, (config_.public_metadata_enabled() == true)
                   ? AddEgressRequest::RequestDestination::kBeryllium
                   : AddEgressRequest::RequestDestination::kBrass);
  request_time_ = absl::Now();

  auto add_egress_http_request = add_egress_request.EncodeToProtoForPpn(params);
  add_egress_http_request.set_url(brass_url_);
  http_fetcher_.PostJsonAsync(
      add_egress_http_request,
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

}  // namespace krypton
}  // namespace privacy
