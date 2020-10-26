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

#ifndef PRIVACY_NET_KRYPTON_SESSION_MANAGER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_SESSION_MANAGER_INTERFACE_H_

#include <optional>

#include "privacy/net/krypton/session.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {

// Interface for managing a session.
class SessionManagerInterface {
 public:
  virtual ~SessionManagerInterface() = default;
  virtual void RegisterNotificationInterface(
      Session::NotificationInterface*) = 0;
  virtual void EstablishSession(absl::string_view zinc_url,
                                absl::string_view brass_url,
                                absl::string_view service_type,
                                int restart_count,
                                absl::optional<NetworkInfo> network_info) = 0;

  // Terminates the session.
  virtual void TerminateSession() = 0;

  // Gets the active session.
  virtual absl::optional<Session*> session() const = 0;
};
}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_SESSION_MANAGER_INTERFACE_H_
