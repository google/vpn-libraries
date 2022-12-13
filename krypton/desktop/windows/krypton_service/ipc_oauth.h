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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_OAUTH_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_OAUTH_H_

#include <string>

#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_krypton_service.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "third_party/absl/status/statusor.h"

// Interface for getting oauth tokens.
namespace privacy {
namespace krypton {
namespace windows {

class IpcOauth : public OAuthInterface {
 public:
  explicit IpcOauth(IpcKryptonService* ipc_handler)
      : ipc_handler_(ipc_handler) {}
  ~IpcOauth() override = default;

  absl::StatusOr<std::string> GetOAuthToken() override;

  absl::StatusOr<privacy::ppn::AttestationData> GetAttestationData(
      const std::string& /*nonce*/) override {
    return absl::UnimplementedError(
        "GetAttestationData() unavailable on Desktop");
  }

 private:
  IpcKryptonService* ipc_handler_;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_KRYPTON_SERVICE_IPC_OAUTH_H_
