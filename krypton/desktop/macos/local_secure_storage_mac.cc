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
#include "privacy/net/krypton/desktop/macos/local_secure_storage_mac.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace desktop {

LocalSecureStorageMac::LocalSecureStorageMac(SecKeychainRef keychain)
    : keychain_(keychain) {}

LocalSecureStorageMac::~LocalSecureStorageMac() { CFRelease(keychain_); }

absl::Status LocalSecureStorageMac::StoreData(absl::string_view key,
                                              absl::string_view value) {
  SecKeychainItemRef item_ref;
  OSStatus find_status = SecKeychainFindGenericPassword(
      keychain_, sizeof(kPpnKeychainName) - 1, kPpnKeychainName, key.size(),
      key.data(), nullptr, nullptr, &item_ref);
  if (find_status == errSecSuccess) {
    OSStatus delete_status = SecKeychainItemDelete(item_ref);
    CFRelease(item_ref);
    if (delete_status != errSecSuccess) {
      return absl::InternalError(
          absl::StrCat("Failed to delete data with key: ", key));
    }
  }

  const OSStatus status = SecKeychainAddGenericPassword(
      keychain_, sizeof(kPpnKeychainName) - 1, kPpnKeychainName, key.size(),
      key.data(), value.size(), value.data(), nullptr);
  if (status == errSecNoDefaultKeychain) {
    return absl::UnavailableError("No Default Keychain found.");
  }
  if (status == errSecDuplicateItem) {
    return absl::AlreadyExistsError(
        absl::StrCat(key, " already exists in Keychain."));
  }
  if (status == errSecDataTooLarge) {
    return absl::AbortedError("Data too large.");
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> LocalSecureStorageMac::FetchData(
    absl::string_view key) {
  UInt32 data_size = 0;
  void* data = nullptr;
  OSStatus status = SecKeychainFindGenericPassword(
      keychain_, sizeof(kPpnKeychainName) - 1, kPpnKeychainName, key.size(),
      key.data(), &data_size, &data, nullptr);
  if (status != errSecSuccess) {
    return absl::InternalError(
        absl::StrCat("Failed to find data with key: ", key));
  }
  std::string ret_content(static_cast<char*>(data), data_size);
  SecKeychainItemFreeContent(nullptr, data);
  return ret_content;
}

absl::Status LocalSecureStorageMac::DeleteData(absl::string_view key) {
  SecKeychainItemRef item_ref;
  OSStatus find_status = SecKeychainFindGenericPassword(
      keychain_, sizeof(kPpnKeychainName) - 1, kPpnKeychainName, key.size(),
      key.data(), nullptr, nullptr, &item_ref);
  if (find_status != errSecSuccess) {
    return absl::InternalError(
        absl::StrCat("Failed to find data with key: ", key));
  }
  OSStatus delete_status = SecKeychainItemDelete(item_ref);
  CFRelease(item_ref);
  if (delete_status != errSecSuccess) {
    return absl::InternalError(
        absl::StrCat("Failed to delete data with key: ", key));
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<LocalSecureStorageMac>>
LocalSecureStorageMac::CreateInstance() {
  SecKeychainRef keychain;
  OSStatus status = SecKeychainCopyDefault(&keychain);
  if (status == errSecNoDefaultKeychain) {
    return absl::NotFoundError("No default keychain found.");
  }
  if (status != errSecSuccess) {
    return absl::InternalError(
        "Unknown error when trying to find default keychain.");
  }

  return std::make_unique<LocalSecureStorageMac>(keychain);
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
