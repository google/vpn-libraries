/*
 * Copyright (C) 2021 Google Inc.
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
#ifndef PRIVACY_NET_KRYPTON_DESKTOP_MACOS_LOCAL_SECURE_STORAGE_MAC_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_MACOS_LOCAL_SECURE_STORAGE_MAC_H_

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace desktop {

class LocalSecureStorageMac : public LocalSecureStorageInterface {
 public:
  explicit LocalSecureStorageMac(SecKeychainRef keychain);

  ~LocalSecureStorageMac() override;

  // Copying is forbidden due to risk of trying to access keychain_ after it
  // has been freed in a copy.
  LocalSecureStorageMac(const LocalSecureStorageMac&) = delete;

  LocalSecureStorageMac(LocalSecureStorageMac&&) = delete;

  LocalSecureStorageMac& operator=(const LocalSecureStorageMac&) = delete;

  LocalSecureStorageMac& operator=(LocalSecureStorageMac&&) = delete;

  absl::Status StoreData(absl::string_view key,
                         absl::string_view value) override;

  absl::StatusOr<std::string> FetchData(absl::string_view key) override;

  absl::Status DeleteData(absl::string_view key) override;

  static absl::StatusOr<std::unique_ptr<LocalSecureStorageMac>>
  CreateInstance();

 private:
  SecKeychainRef keychain_;
  static constexpr char kPpnKeychainName[] = "com.google.one.mac.vpn";
};

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_MACOS_LOCAL_SECURE_STORAGE_MAC_H_
