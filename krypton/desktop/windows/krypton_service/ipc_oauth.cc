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

#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_oauth.h"

#include <string>

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/utils/status.h"

namespace privacy {
namespace krypton {
namespace windows {

absl::StatusOr<std::string> IpcOauth::GetOAuthToken() {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::FETCH_OAUTH_TOKEN);
  desktop::KryptonControlMessage response;
  PPN_ASSIGN_OR_RETURN(response, ipc_handler_->CallPipe(request));
  if (response.response().status().code() != google::rpc::Code::OK) {
    return utils::GetStatusFromRpcStatus(response.response().status());
  }
  return response.response().fetch_outh_token_response().oauth_token();
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
