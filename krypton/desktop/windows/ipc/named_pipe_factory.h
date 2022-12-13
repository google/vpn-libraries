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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_FACTORY_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_FACTORY_H_

#include <memory>
#include <string>

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory_interface.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {

class NamedPipeFactory : public NamedPipeFactoryInterface {
 public:
  NamedPipeFactory() = default;
  ~NamedPipeFactory() override = default;

  /** Connect to pipe from Client in sync. **/
  absl::StatusOr<std::unique_ptr<NamedPipeInterface>> ConnectToPipeOnServer(
      const std::string& pipe_name) const;

  /** Create a pipe instance with pipe_name. **/
  absl::StatusOr<std::unique_ptr<NamedPipeInterface>> CreateNamedPipeInstance(
      const std::string& pipe_name) const;

 private:
  absl::StatusOr<std::unique_ptr<NamedPipeInterface>> InitializeNamedPipe(
      HANDLE pipe) const;

  /** Create Security Descriptor with file all access rights for current user
   * and Read/Write rights for LocalSystem. **/
  absl::StatusOr<PSECURITY_DESCRIPTOR> GetSecurityDescriptor() const;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_IPC_NAMED_PIPE_FACTORY_H_
