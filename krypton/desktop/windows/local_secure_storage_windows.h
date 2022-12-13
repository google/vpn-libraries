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
#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOCAL_SECURE_STORAGE_WINDOWS_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOCAL_SECURE_STORAGE_WINDOWS_H_

#include <string>

#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace desktop {

class LocalSecureStorageWindows : public LocalSecureStorageInterface {
 public:
  absl::Status StoreData(absl::string_view key,
                         absl::string_view value) override;
  absl::StatusOr<std::string> FetchData(absl::string_view key) override;
  absl::Status DeleteData(absl::string_view key) override;

 private:
  static constexpr char kPpnRefreshKeyPrefix[] = "ppn_desktop_win_refresh_key";
};

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_LOCAL_SECURE_STORAGE_WINDOWS_H_
